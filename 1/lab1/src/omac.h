#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "magma_calc.h"

void uint64_to_bytes(uint64_t num, uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[i] = (num >> (56 - i * 8)) & 0xFF;
    }
}

void bytes_to_uint64(const uint8_t *bytes, uint64_t *num) {
    *num = 0;
    for (int i = 0; i < 8; i++) {
        *num = (*num << 8) | bytes[i];
    }
}

int OMAC_File(const char *filename, uint8_t *mac) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    // Генерация K1 и K2
    uint8_t L[BLOCK_SIZE] = {0};
    GOST_Magma_Encrypt(L, L);

    uint64_t L_num, K1_num, K2_num;
    bytes_to_uint64(L, &L_num);
    
    const uint64_t Rb = 0x1BULL << 56;
    uint8_t carry = (L_num >> 63) & 1;
    K1_num = (L_num << 1) ^ (carry ? Rb : 0);
    
    carry = (K1_num >> 63) & 1;
    K2_num = (K1_num << 1) ^ (carry ? Rb : 0);

    uint8_t K1[BLOCK_SIZE], K2[BLOCK_SIZE];
    uint64_to_bytes(K1_num, K1);
    uint64_to_bytes(K2_num, K2);

    // CBC-MAC processing
    uint8_t T[BLOCK_SIZE] = {0};
    uint8_t block[BLOCK_SIZE];
    size_t bytes_read;
    int is_last_block = 0;
    size_t total_bytes = 0;

    while ((bytes_read = fread(block, 1, BLOCK_SIZE, file)) > 0) {
        total_bytes += bytes_read;
        
        if (feof(file)) {
            is_last_block = 1;
            if (bytes_read < BLOCK_SIZE || ftell(file) == 0) {
                // Дополнение последнего блока
                if (bytes_read < BLOCK_SIZE) {
                    block[bytes_read] = 0x80;
                    memset(block + bytes_read + 1, 0, BLOCK_SIZE - bytes_read - 1);
                }
                for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= K2[i];
            } else {
                // Если файл заканчивается полным блоком - используем предыдущий блок
                fseek(file, -BLOCK_SIZE * 2, SEEK_END);
                fread(block, 1, BLOCK_SIZE, file);
                for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= K1[i];
                is_last_block = 0;  // Нужно обработать два последних блока
            }
        }

        // XOR с предыдущим результатом
        for (int i = 0; i < BLOCK_SIZE; i++) T[i] ^= block[i];
        
        GOST_Magma_Encrypt(T, T);
        
        if (is_last_block) break;
    }

    // Обработка пустого файла
    if (total_bytes == 0) {
        memset(block, 0, BLOCK_SIZE);
        block[0] = 0x80;
        for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= K2[i];
        for (int i = 0; i < BLOCK_SIZE; i++) T[i] ^= block[i];
        GOST_Magma_Encrypt(T, T);
    }

    fclose(file);
    memcpy(mac, T, BLOCK_SIZE);
    return 0;
}