#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <memory.h>

#include "hash.h"
#include "cuckoo_filter.h"

uint32_t g_pri_idx, g_sec_idx;
uint8_t g_fingerprint;

static uint32_t
cf_bucket_empty(struct cuckoo_filter *cf, uint32_t idx) {
	if (!cf || !cf->hash_table || !cf->hash_table->bkt_count) {
		return NOT_EXIST;
	}
	if (cf->hash_table->bkt_count[idx] < cf->hash_table->nb_entry_bkt) {
		return EXIST;
	}
	return NOT_EXIST;
}

static fp_ptr
cf_fingerprint(struct hash_table *ht, uint8_t *data,
			  uint32_t len, fp_ptr fp) {
	uint32_t init_val;

	init_val = GENERAL_HASH_INITIAL_VALUE;
	init_val = hash_u32(data, len, init_val);
	memcpy(fp, &init_val, ht->sz_entry);
	return fp;
}

static uint32_t
cf_hash(struct hash_table *ht, uint8_t *data,
		 uint32_t len) {
	uint8_t i;
	uint8_t *val8;
	uint32_t *val;
	uint32_t init_val;
	uint32_t temp;

	val = (uint32_t*)data;
	init_val = HASH_INDEX_INITIAL_VALUE;
	for (i = 0; i < len/4; ++i) {
		init_val = crc32c_sse_u32(val[i], init_val);
	}
	val8 = data + len/4*4;
	temp = 0;
	if (len & 0x10) {
		temp += ((uint16_t*)val8)[0];
	}
	if (len & 0x1) {
		temp += ((val8 + 16)[0] << 16);
	}
	init_val = crc32c_sse_u32(temp, init_val);
	return init_val%(ht->nb_bkt);
}

static uint32_t
cf_cmp_eq(uint8_t *data1, uint8_t *data2, uint32_t len) {
	uint32_t i;
	
	for (i = 0; i < len; ++i) {
		if (data1[i] != data2[i]) {
			return FAILURE;
		}
	}
	return SUCCESS;
}

static uint32_t
__cf_swap(uint8_t *data1, uint8_t *data2, uint32_t len) {
	uint8_t temp;
	uint32_t i;
	
	for (i = 0; i < len; ++i) {
		temp = data1[i];
		data1[i] = data2[i];
		data2[i] = temp;
	}
	return 0;
}
struct hash_table *ht_init(uint32_t max_len, uint32_t nb_bkt,
			   uint32_t nb_entry_bkt, uint32_t sz_entry) {
	struct hash_table *ht;

	/* Validate bounds every variable. */
	if (max_len > MAX_TABLE_BYTE) {
		printf("max_len is invalid beyond %u.\n", MAX_TABLE_BYTE);
		return NULL;
	}
	if (nb_bkt > MAX_TABLE_SIZE) {
		printf("nb_bkt is invalid beyond %u.\n", MAX_TABLE_SIZE);
		return NULL;
	}
	if (nb_entry_bkt > MAX_BUCKET_SIZE) {
		printf("nb_entry_bkt is invalid beyond %u.\n", MAX_BUCKET_SIZE);
		return NULL;
	}
	if (sz_entry > MAX_SIZE_ENTRY) {
		printf("sz_entry is invalid beyond %u.\n", MAX_SIZE_ENTRY);
		return NULL;
	}
	if (max_len < nb_bkt*nb_entry_bkt*sz_entry) {
		printf("max_len is too small.\n");
		return NULL;
	}

	/* Allocate room for table. */
	ht = (struct hash_table *)malloc(sizeof(struct hash_table));
	ht->table = (uint8_t *)malloc(max_len);
	if (!ht->table) {
		printf("Memory is too small to allocate for table.\n");
		free(ht);
		return NULL;
	}

	/* Allocate room for counting of bucket. */
	ht->bkt_count = (uint8_t *)malloc(nb_bkt);
	if (!ht->bkt_count) {
		printf("Memory is too small to allocate for bkt_count.\n");
		free(ht->table);
		free(ht);
		return NULL;
	}

	memset(ht->table, 0, max_len);
	memset(ht->bkt_count, 0, nb_bkt);
	ht->max_len = max_len;
	ht->nb_bkt = nb_bkt;
	ht->nb_entry_bkt = nb_entry_bkt;
	ht->sz_entry = sz_entry;
	ht->bitmask = (ENTRY_MASK >> (MAX_SIZE_ENTRY - ht->sz_entry));
	return ht;
}

uint32_t debug_print(struct hash_table *ht) {
	uint32_t i, j, k;
	uint32_t sz_bkt;

	if (!ht) {
		return SUCCESS;
	}
	
	sz_bkt = ht->sz_entry*ht->nb_entry_bkt;
	for (i = 0; i < ht->nb_bkt; ++i) {
		printf("In Bucket %u: ", i);
		for (j = 0; j < ht->bkt_count[i]; ++j) {
			printf("0x");
			for (k = 0; k < ht->sz_entry; ++k) {
				printf("%x", *(ht->table + sz_bkt*i + ht->sz_entry*j+k));
			}
			printf(" ");
		}
		printf("\n");
	}
	printf("Debug Finished!\n");
	return SUCCESS;
}

uint32_t ht_delete(struct hash_table *ht) {
	if (ht) {
		free(ht->table);
	}
	return SUCCESS;
}

struct cuckoo_filter* cf_init(struct hash_table_param *ht_param) {
	struct cuckoo_filter *cf;
	struct hash_table *ht;
	
	cf = (struct cuckoo_filter*)malloc(sizeof(struct cuckoo_filter));
	if (!cf) {
		printf("Memory is too small to allocate for cuckoo filter.\n");
		return NULL;
	}

	/**
	 * Here is parameter of hash table:
	 *   Maximum length, number of buckets, 
	 *   number of entries in bucket, size of entry.
	 */
	ht = ht_init(ht_param->max_len, ht_param->nb_bkt,
		     ht_param->nb_entry_bkt, ht_param->sz_entry);
	if (!ht) {
		printf("Failure when initializing hash table!\n");
		free(cf);
		return NULL;
	}
	cf->hash_table = ht;
	return cf;
}

uint32_t cf_insert(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen) {
	uint32_t primary_idx, secondary_idx;
	uint32_t idx;
	struct hash_table *ht;
	fp_ptr fp;
	uint32_t bkt_sz;
	uint32_t sz_entry;
	uint32_t entry_pos;
	uint32_t i;

	ht = cf->hash_table;
	bkt_sz = ht->sz_entry*ht->nb_entry_bkt;
	sz_entry = ht->sz_entry;

	/* Calculate fingeprint and primary and secondary index. */
	fp = (fp_ptr)malloc(ht->sz_entry);
	cf_fingerprint(ht, key, klen, fp);
	primary_idx = cf_hash(ht, key, klen);
	secondary_idx = cf_hash(ht, fp, sz_entry) ^ primary_idx;

	g_pri_idx = primary_idx;
	g_sec_idx = secondary_idx;
	g_fingerprint = fp[0];

	/* Judge whether there is idle room. */
	if (cf_bucket_empty(cf, primary_idx) == EXIST) {
		entry_pos = ht->bkt_count[primary_idx];
		memcpy(ht->table + bkt_sz*primary_idx + entry_pos*sz_entry, fp, sz_entry);
		ht->bkt_count[primary_idx] += 1;
		return SUCCESS;
	}
	if (cf_bucket_empty(cf, secondary_idx) == EXIST) {
		entry_pos = ht->bkt_count[secondary_idx];
		memcpy(ht->table + bkt_sz*secondary_idx+entry_pos*sz_entry, fp, sz_entry);
		ht->bkt_count[secondary_idx] += 1;
		return SUCCESS;
	}

	idx = primary_idx;
	/* Relocate existing items. */
	for (i = 0; i < MAX_CUCKOO_FILTER_TRIES; ++i) {
		__cf_swap(fp, ht->table + idx*bkt_sz, sz_entry);
		idx = cf_hash(ht, fp, sz_entry) ^ idx;
		if (cf_bucket_empty(cf, idx) == EXIST) {
			entry_pos = ht->bkt_count[idx];
			memcpy(ht->table + bkt_sz*idx + entry_pos*sz_entry, fp, sz_entry);
			ht->bkt_count[idx] += 1;
			return SUCCESS;
		}
	}
	return FAILURE;
}

uint32_t cf_delete(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen) {
	uint32_t primary_idx, secondary_idx;
	uint32_t idx;
	struct hash_table *ht;
	fp_ptr fp;
	uint32_t bkt_sz;
	uint32_t sz_entry;
	uint32_t i;

	ht = cf->hash_table;
	bkt_sz = ht->sz_entry*ht->nb_entry_bkt;
	sz_entry = ht->sz_entry;

	/* Calculate fingerprint and primary and secondary index. */
	fp = (fp_ptr)malloc(ht->sz_entry);
	cf_fingerprint(ht, key, klen, fp);
	primary_idx = cf_hash(ht, key, klen);
	secondary_idx = cf_hash(ht, fp, sz_entry) ^ primary_idx;

	/* Judge whether there is the fingerprint in two bucket. */
	for (i = 0; i < ht->bkt_count[primary_idx]; ++i) {
		idx = primary_idx*bkt_sz + sz_entry*i;
		if (cf_cmp_eq(ht->table + idx, fp, sz_entry) == SUCCESS) {
			memcpy(ht->table + idx,
			       ht->table + idx + sz_entry,
			       sz_entry*(ht->bkt_count[primary_idx] - i - 1));
			ht->bkt_count[primary_idx] -= 1;
			return SUCCESS;
		}
	}
	for (i = 0; i < ht->bkt_count[secondary_idx]; ++i) {
		idx = secondary_idx*bkt_sz + sz_entry*i;
		if (cf_cmp_eq(ht->table + idx, fp, sz_entry) == SUCCESS) {
			memcpy(ht->table + idx,
			       ht->table + idx + sz_entry,
			       sz_entry*(ht->bkt_count[secondary_idx] - i - 1));
			ht->bkt_count[secondary_idx] -= 1;
			return SUCCESS;
		}
	}
	return FAILURE;
}

uint32_t cf_lookup(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen) {
	uint32_t primary_idx, secondary_idx;
	uint32_t idx;
	struct hash_table *ht;
	fp_ptr fp;
	uint32_t bkt_sz;
	uint32_t sz_entry;
	uint32_t i;

	ht = cf->hash_table;
	bkt_sz = ht->sz_entry*ht->nb_entry_bkt;
	sz_entry = ht->sz_entry;

	/* Calculate fingerprint and primary and secondary index. */
	fp = (fp_ptr)malloc(ht->sz_entry);
	cf_fingerprint(ht, key, klen, fp);
	primary_idx = cf_hash(ht, key, klen);
	secondary_idx = cf_hash(ht, fp, sz_entry) ^ primary_idx;

	/* Judge whether there is the fingerprint in two bucket. */
	for (i = 0; i < ht->bkt_count[primary_idx]; ++i) {
		idx = primary_idx*bkt_sz + sz_entry*i;
		if (cf_cmp_eq(ht->table + idx, fp, sz_entry) == SUCCESS) {
			return SUCCESS;
		}
	}
	for (i = 0; i < ht->bkt_count[secondary_idx]; ++i) {
		idx = secondary_idx*bkt_sz + sz_entry*i;
		if (cf_cmp_eq(ht->table + idx, fp, sz_entry) == SUCCESS) {
			return SUCCESS;
		}
	}
	return FAILURE;
}
