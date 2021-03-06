#include <stdio.h>
#include <stdlib.h>

#include "bloom_filter.h"
#include "cuckoo_filter.h"

extern uint32_t g_pri_idx, g_sec_idx;
extern uint8_t g_fingerprint;

#define N 128

uint32_t A[N];

int main() {
	struct cuckoo_filter *cf;
	struct hash_table_param ht_param;
	uint32_t x;
	uint32_t i;
	uint32_t flag;
	uint32_t count;
	
	srand(47);
	for (i = 0; i < N; ++i) {
		A[i] = rand();
		printf("%u ", A[i]);
	}
	printf("\n");
	ht_param.max_len = 1000;
	ht_param.nb_bkt = 64;
	ht_param.nb_entry_bkt = 4;
	ht_param.sz_entry = 1;
	cf = cf_init(&ht_param);
	count = 0;
	for (i = 0; i < N; ++i) {
		x = i;
		flag = cf_insert(cf, &x, sizeof(x));
		count += flag;
//		printf("Insert %s!\n", flag?"Success":"Failure");
//		printf("NO %u:primary:%u secondary:%u fingerprint:0x%x\n",
//			i, g_pri_idx, g_sec_idx, g_fingerprint);
//			debug_print(cf->hash_table);
//		printf("\n");
	}
	printf("Rate of Success of insertion:%u/%u\n", count, N);
	
	count = 0;
	for (i = 0; i < N; ++i) {
		x = A[i];
		flag = cf_lookup(cf, &x, sizeof(x));
		count += flag;
	}
	printf("Rate of Success of lookup:%u/%u\n", count, N);

	count = 0;
	for (i = 0; i < N; ++i) {
		x = A[i];
		flag = cf_delete(cf, &x, sizeof(x));
		count += flag;
	}
	printf("Rate of Success of deletion:%u/%u\n", count, N);
	debug_print(cf->hash_table);

	/* Bloom Filter */
	printf("Bloom Filter:\n");
 	struct bloom_filter *bf;
 	bf = bf_init(256, 3);
	
	count = 0;
	for (i = 0; i < N; ++i) {
		x = A[i];
		flag = bf_insert(bf, &x, sizeof(x));
		count += flag;
	}
	printf("Rate of Success of insertion:%u/%u\n", count, N);

	count = 0;
	for (i = 0; i < N; ++i) {
		x = A[i];
		flag = bf_lookup(bf, &x, sizeof(x));
		count += flag;
	}
	printf("Rate of Success of lookup:%u/%u\n", count, N);
 	bf_print(bf);

	return 0;
}
