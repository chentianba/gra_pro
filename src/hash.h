#ifndef HASH_H
#define HASH_H

#include <inttypes.h>

#define GENERAL_HASH_INITIAL_VALUE 47

/**
 * A collection of hash functions generated according to
 * different initial value.
 *
 * @param data
 *   The 32-bit key that will be hashed.
 * @param init_val
 *   The 32-bit initial value used to hash the key.
 * @return
 *   The 32-bit result of hashing with key and initial value.
 */
static inline uint32_t
crc32c_sse_u32(uint32_t data, uint32_t init_val) {
	__asm__ volatile(
			"crc32l %[data], %[init_val];"
			: [init_val] "+r" (init_val)
			: [data] "rm" (data));
	return init_val;
}

static inline uint32_t
hash_u32(uint8_t *data, uint32_t len, uint32_t init_val) {
	uint32_t i;
	uint32_t *val;
	uint32_t idx;
	uint32_t temp;

	val = (uint32_t *)data;
	for (i = 0; i < len/4; ++i) {
		init_val = crc32c_sse_u32(val[i], init_val);
	}
	idx = len/4*4;
	temp = 0;
	for (i = 0; i < (len & 0x11); ++i) {
		temp += ((data + idx + i)[0] << (i*8));
	}
	init_val = crc32c_sse_u32(temp, init_val);
	return init_val;
}

#endif
