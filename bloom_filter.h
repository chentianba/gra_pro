#include <inttypes.h>


#define BF_MAX_SIZE 100
#define MAX_HASH_FUNC 10


typedef uint32_t (*hash_func)(uint32_t key, uint32_t init_val);


struct bloom_filter {
	uint8_t *filter;
	uint32_t length;
	hash_func hash_func;
	uint32_t *hash_init_val;
	uint32_t nb_hash;
};

static inline uint32_t
crc32c_sse_u32(uint32_t data, uint32_t init_val) {
	__asm__ volatile(
			"crc32l %[data], %[init_val];"
			: [init_val] "+r" (init_val)
			: [data] "rm" (data));
	return init_val;
}

struct bloom_filter* bf_init(uint32_t bf_sz, uint32_t nb_hash);

uint32_t bf_add(struct bloom_filter *bf, uint32_t key);

uint32_t bf_lookup(struct bloom_filter *bf, uint32_t key);

uint32_t bf_set(struct bloom_filter* bf, uint32_t index);

uint32_t bf_clear(struct bloom_filter* bf, uint32_t index);

uint32_t bf_print(struct bloom_filter* bf);
