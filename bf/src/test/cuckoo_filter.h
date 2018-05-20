#include <inttypes.h>

#define MAX_BUCKET_SIZE 4
#define MAX_TABLE_SIZE 10000
#define MAX_TABLE_BYTE 1000000
#define MAX_SIZE_ENTRY 4
#define ENTRY_MASK 0x11111111

#define HASH_INDEX_INITIAL_VALUE 23

#define MAX_CUCKOO_FILTER_TRIES 100

#define SUCCESS 1
#define FAILURE 0
#define EXIST 1
#define NOT_EXIST 0


struct hash_table {
	uint8_t *table;             /* Space containing all buckets. */
	uint32_t max_len;           /* Number of byte in table. */

	uint32_t nb_bkt;            /* Number of all bucket in table. */
	uint32_t nb_entry_bkt;      /* Number every bucket. */
	uint32_t sz_entry;          /* Number of byte every entry */
	uint32_t bitmask;	    /* Bit mask */

	uint8_t *bkt_count;	    /* Count existing entries for every bucket. */
};

struct hash_table_param {
	uint32_t max_len;           /* Number of byte in table. */
	uint32_t nb_bkt;            /* Number of all bucket in table. */
	uint32_t nb_entry_bkt;      /* Number every bucket. */
	uint32_t sz_entry;          /* Number of byte every entry */
};

struct cuckoo_filter {
	struct hash_table *hash_table;
};

typedef uint8_t *fp_ptr;

extern uint32_t g_pri_idx, g_sec_idx;
extern uint8_t g_fingerprint;

struct hash_table *ht_init(uint32_t max_len, uint32_t nb_bkt,
			   uint32_t nb_entry_bkt, uint32_t sz_entry);

uint32_t ht_delete(struct hash_table *ht);

struct cuckoo_filter* cf_init(struct hash_table_param*);

uint32_t cf_insert(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen);

uint32_t cf_delete(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen);

uint32_t cf_lookup(struct cuckoo_filter *cf, uint8_t *key, uint32_t klen);

uint32_t debug_print(struct hash_table*);
