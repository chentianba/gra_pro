#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <inttypes.h>

#include "bloom_filter.h"
#include "hash.h"


struct bloom_filter* bf_init(uint32_t bf_sz, uint32_t nb_hash) {
	struct bloom_filter *bf;
	uint32_t size;
	unsigned int i;

	/* init the filter of struct bloom_filter */
	if (bf_sz > BF_MAX_SIZE) {
		printf("Cannot get so large filter!\n");
		return NULL;
	}
	bf = (struct bloom_filter*)malloc(sizeof(struct bloom_filter));
	if (!bf) {
		printf("Cannot init struct bloom_filter!");
		return NULL;
	}
	size = (bf_sz + 7)/8;
	bf->filter = (uint8_t*) malloc(size);
	if (!bf->filter) {
		free(bf);
		printf("Not enough memory!\n");
		return NULL;
	}

	bf->length = bf_sz;
	memset(bf->filter, 0, size);

	/* init the hash functions */
	if (nb_hash > MAX_HASH_FUNC) {
		printf("Number of hash functions is so large"
			" and max is %u.\n", MAX_HASH_FUNC);
		nb_hash = MAX_HASH_FUNC;
	}
	bf->hash_func = hash_u32;
	bf->hash_init_val = (uint32_t *)malloc(sizeof(uint32_t)*nb_hash);
	bf->nb_hash = nb_hash;
	srand(GENERAL_HASH_INITIAL_VALUE);
	for (i = 0; i < nb_hash; ++i) {
		bf->hash_init_val[i] = rand();
	}
	
	return bf;
}

uint32_t bf_insert(struct bloom_filter *bf, uint8_t *key, uint32_t klen) {
	uint32_t i;
	uint32_t pos;
	
	if (!bf) {
		return FAILURE;
	}

	for (i = 0; i < bf->nb_hash; ++i) {
		pos = bf->hash_func(key, klen, bf->hash_init_val[i])%bf->length;
		if (bf_set(bf, pos) == FAILURE)
			return FAILURE;
	}
	return SUCCESS;
}

uint32_t bf_lookup(struct bloom_filter *bf, uint8_t *key, uint32_t klen) {
	uint32_t i;
	uint32_t val, mask;
	uint32_t pos;

	if (!bf) {
		return FAILURE;
	}

	for (i = 0; i < bf->nb_hash; ++i) {
		pos = bf->hash_func(key, klen, bf->hash_init_val[i])%bf->length;
		val = bf->filter[pos/8];
		mask = ((uint8_t)1) << (pos%8);
		if (!(val & mask)) {
			return FAILURE;
		}
	}
	return SUCCESS;
}

uint32_t bf_set(struct bloom_filter* bf, uint32_t index) {
	uint32_t nb_byte;
	uint32_t quot;

	/* Judge whether bf and index is valid. */
	if (!bf) {
		return FAILURE;
	}
	if (index >= bf->length) {
		printf("Index is out of bound!\n");
		return FAILURE;
	}
 	nb_byte = index/8;
 	quot = index%8;
	bf->filter[nb_byte] |= (((uint8_t)1) << quot);
	return SUCCESS;
}

uint32_t bf_clear(struct bloom_filter* bf, uint32_t index) {
	uint32_t nb_byte;
	uint32_t quot;

	/* Judge whether bf and index is valid. */
	if (!bf) {
		return FAILURE;
	}
	if (index >= bf->length) {
		printf("Index is out of bound!\n");
		return FAILURE;
	}
 	nb_byte = index/8;
 	quot = index%8;
	bf->filter[nb_byte] &= (~(((uint8_t)1) << quot));
	return SUCCESS;
}

uint32_t bf_print(struct bloom_filter* bf) {
	uint32_t idx;
	uint8_t val;
	uint8_t mask;
	
	if (!bf) {
		return FAILURE;
	}

	/* val decides on byte and mask decides on bit. */
	for (idx = 0; idx < bf->length; ++idx) {
		val = bf->filter[idx/8];
		mask = ((uint8_t)1) << (idx%8);
		// printf("%d ", (val & mask) != 0); 
		if ((val & mask) == 1)
			printf("%d ", idx);
	}
	printf("\n");
	return SUCCESS;
}

