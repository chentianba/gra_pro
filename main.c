#include <stdio.h>

#include "algorithm.h"

int main() {
	struct bloom_filter *bf;
	bf = bf_init(10);
	bf_print(bf);
	bf_set(bf, 5);
	bf_set(bf, 1);
	bf_print(bf);
	printf("Hello World!\n");
	return 0;
}
