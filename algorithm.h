#include <inttypes.h>


#define BF_MAX_SIZE 100

struct bloom_filter {
	uint8_t *filter;
	uint32_t length;
};

struct bloom_filter* bf_init(uint32_t bf_sz);

uint8_t bf_set(struct bloom_filter* bf, uint32_t index);

uint8_t bf_clear(struct bloom_filter* bf, uint32_t index);

uint8_t bf_print(struct bloom_filter* bf);
