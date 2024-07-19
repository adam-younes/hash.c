#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define DWORD 32
#define RIGHTROTATE(word, bits) (((word) >> (bits)) | ((word) << (DWORD - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y. z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define E0(x) (RIGHTROTATE(x, 2)) ^ (RIGHTROTATE(x, 13)) ^ (RIGHTROTATE(x, 22))
#define E1(x) (RIGHTROTATE(x, 6) ^ RIGHTROTATE(x, 11) ^ RIGHTROTATE(x, 25))
#define S0(x) (RIGHTROTATE(x, 7) ^ RIGHTROTATE(x, 18) ^ ((x) >> 3))
#define S1(x) (RIGHTROTATE(x, 17) ^ RIGHTROTATE(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {

}

