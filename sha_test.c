#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

int main(void) {
  int input = 61;
  
  char hash[DWORD];

  sha256((const uint8_t *)input, BYTE, hash);

  printf("Hash: %02x", hash);
}
