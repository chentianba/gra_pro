#include <stdio.h>

#include "bloom_filter.h"

int main() {
	struct bloom_filter *bf;
	bf = bf_init(10, 3);
	printf("%u\n", bf_add(bf, 124));
	bf_print(bf);
	printf("%u\n", bf_add(bf, 14));
	bf_print(bf);
	printf("%u\n", bf_lookup(bf, 124));
	bf_print(bf);
	printf("Hello World!\n");
	return 0;
}
