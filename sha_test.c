#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

int main() {
    const char *input = "Hello, world!";
    uint8_t hash[32];
    size_t len = strlen(input);

    sha256((const uint8_t *)input, len, hash);

    printf("SHA-256 hash: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
