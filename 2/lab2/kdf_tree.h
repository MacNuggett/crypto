#ifndef KDF_TREE_H
#define KDF_TREE_H

#include <openssl/evp.h>
#include <stdint.h>

#define GOST3411_256_DIGEST_SIZE 32

int KDF_TREE_GOSTR3411_2012_256(
    const uint8_t *K,
    size_t K_len,
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    uint32_t R,
    uint32_t L,
    uint8_t *out);

void print_hex(const char* label, const uint8_t* data, size_t len);

#endif // KDF_TREE_H