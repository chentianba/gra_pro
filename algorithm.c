#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <inttypes.h>

#include "algorithm.h"


struct bloom_filter* bf_init(uint32_t bf_sz) {
	struct bloom_filter *bf;
	uint32_t size;

	/* init struct bloom_filter */
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
	
	return bf;
}

uint8_t bf_set(struct bloom_filter* bf, uint32_t index) {
	uint32_t nb_byte = index/8;
	uint32_t quot = index%8;

	if (!bf) {
		return 0;
	}
	bf->filter[nb_byte] |= (((uint8_t)1) << quot);
	return 1;
}

uint8_t bf_clear(struct bloom_filter* bf, uint32_t index) {
	uint32_t nb_byte = index/8;
	uint32_t quot = index%8;

	if (!bf) {
		return 0;
	}
	bf->filter[nb_byte] &= (~(((uint8_t)1) << quot));
	return 1;
}

uint8_t bf_print(struct bloom_filter* bf) {
	uint32_t idx;
	uint8_t val;
	uint8_t mask;
	
	if (!bf) {
		return 0;
	}

	/* val decides on byte and mask decides on bit. */
	for (idx = 0; idx < bf->length; ++idx) {
		val = bf->filter[idx/8];
		mask = ((uint8_t)1) << (idx%8);
		printf("%d ", (val & mask) != 0); 
	}
	printf("\n");
	return 1;
}

