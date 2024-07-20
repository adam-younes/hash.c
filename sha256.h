//SHA 256 implementation
#ifndef SHA_256
#define SHA_256

#include <stdint.h>
#include <stddef.h>

// right rotation operation
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
// choose function, uses x to choose between the bits of y and z
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
// majority function, uses the bit that the majority of x, y, and z have
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
// bigsig functions, series of xors
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
// lilsig functions, series of xors and bitshift
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// k constants
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief Transforms the state based on a single 512-bit block of data.
 * 
 * @param state The current hash state (array of 8 32-bit words).
 * @param data The input data block to process (array of 64 bytes).
 */
void sha256_transform(uint32_t state[8], const uint8_t data[64]);
/**
 * @brief Initializes the SHA-256 state.
 * 
 * @param state The hash state to initialize (array of 8 32-bit words).
 */
void sha256_init(uint32_t state[8]);

/**
 * @brief Updates the SHA-256 state with new input data.
 * 
 * @param state The current hash state (array of 8 32-bit words).
 * @param buffer The data buffer (array of 64 bytes).
 * @param data The input data to process.
 * @param len The length of the input data.
 * @param bitlen The total length of the processed data in bits (array of 2 64-bit words).
 */
void sha256_update(uint32_t state[8], uint8_t buffer[64], const uint8_t data[], size_t len, uint64_t bitlen[2]);

/**
 * @brief Finalizes the SHA-256 hash computation and produces the final hash.
 * 
 * @param state The current hash state (array of 8 32-bit words).
 * @param buffer The data buffer (array of 64 bytes).
 * @param hash The output hash (array of 32 bytes).
 * @param bitlen The total length of the processed data in bits (array of 2 64-bit words).
 */
void sha256_final(uint32_t state[8], uint8_t buffer[64], uint8_t hash[32], uint64_t bitlen[2]);

/**
 * @brief Computes the SHA-256 hash of the input data.
 * 
 * @param data The input data to hash.
 * @param len The length of the input data.
 * @param hash The output hash (array of 32 bytes).
 */
void sha256(const uint8_t data[], size_t len, uint8_t hash[32]);

#endif // SHA_256
