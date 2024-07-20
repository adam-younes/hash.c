#include "sha256.h"

void sha256_transform(uint32_t state[BYTE], const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[QWORD];

  for (i = 0 ; i < DWORD ; i++, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
  for (; i < 64 ; i++)
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  for (i = 0 ; i < QWORD ; i++) {
    t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void sha256_init(uint32_t state[BYTE]) {
  state[0] = 0x6a09e667;
  state[1] = 0xbb67ae85;
  state[2] = 0x3c6ef372;
  state[3] = 0xa54ff53a;
  state[4] = 0x510e527f;
  state[5] = 0x9b05688c;
  state[6] = 0x1f83d9ab;
  state[7] = 0x5be0cd19;
}

void sha256_update(uint32_t state[BYTE], uint8_t buffer[QWORD], const uint8_t data[], size_t len, uint64_t bitlen[2]) {
  size_t i;

  for (i = 0 ; i < len ; i++) {
    buffer[bitlen[0] >> 3 & 63] = data[i];
    if ((bitlen[0] += BYTE) == 0) bitlen[i]++;
    if ((bitlen[0] & 511) == 0) sha256_transform(state, buffer);
  }
}

void sha256_final(uint32_t state[BYTE], uint8_t buffer[QWORD], uint8_t hash[DWORD], uint64_t bitlen[2]) {
  uint32_t i;

  i = bitlen[0] >> 3 & 63;
  buffer[i++] = 0x80;
  if (i > SBYTE) {
    while (i < QWORD)
      buffer[i++] = 0x00;
    sha256_transform(state, buffer);
    i = 0;
  }

  while (i < SBYTE)
    buffer[i++] = 0x00;
  for (i = 0 ; i < BYTE ; i++) 
    buffer[63 - i] = bitlen[i >> 2] >> ((i & 3) << 3);
  sha256_transform(state, buffer);
  for (i = 0 ; i < 8 ; i++) {
    hash[i << 2] = state[i] >> SWORD;
    hash[i << 2 | 1] = state[i] >> WORD;
    hash[i << 2 | 2] = state[i] >> BYTE;
    hash[i << 2 | 3] = state[i];
  }
}

void sha256(const uint8_t data[], size_t len, uint8_t hash[DWORD]) {
  uint32_t state[BYTE];
  uint8_t buffer[QWORD];
  uint64_t bitlen[2] = { 0, 0 };

  sha256_init(state);
  sha256_update(state, buffer, data, len, bitlen);
  sha256_final(state, buffer, hash, bitlen);
}
