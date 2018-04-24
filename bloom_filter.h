#include <inttypes.h>
#include "hash.h"

#define BF_MAX_SIZE 10000
#define MAX_HASH_FUNC 10

/* Define the flag of function. */
#ifndef SUCCESS
#define SUCCESS 1
#endif
#ifndef FAILURE
#define FAILURE 0
#endif

typedef uint32_t (*hash_func)(uint8_t *key, uint32_t len, uint32_t init_val);


struct bloom_filter {
	uint8_t *filter;             /* a tuple storing hash bit. */
	uint32_t length;             /* Number of filter bit. */
	hash_func hash_func;         /* A collection of hash functions. */
	uint32_t *hash_init_val;     /* Array of initial value of a hash function. */
	uint32_t nb_hash;            /* Number of hash functions. */
};

/**
 * Initialize the bloom filter.
 * 
 * @param bf_sz
 *   The size of bit array.
 * @param nb_hash
 *   The number of hash funtions.
 * @return
 *   Pointer to the struct of bloom filter when success, otherwise NULL.
 */
struct bloom_filter* bf_init(uint32_t bf_sz, uint32_t nb_hash);

/* Insert the key into the struct. */
uint32_t bf_insert(struct bloom_filter *bf, uint8_t *key, uint32_t klen);

/* Lookup in term of key in bloom filter. */
uint32_t bf_lookup(struct bloom_filter *bf, uint8_t *key, uint32_t klen);

/* Set in the position of index. */
uint32_t bf_set(struct bloom_filter* bf, uint32_t index);

/* Unset in the position of index. */
uint32_t bf_clear(struct bloom_filter* bf, uint32_t index);

/* Debug function: Print every bit of filter in bloom filter. */
uint32_t bf_print(struct bloom_filter* bf);
