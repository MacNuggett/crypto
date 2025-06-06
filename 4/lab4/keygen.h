#ifndef KEYGEN_H
#define KEYGEN_H

#include <stddef.h>
#include <stdint.h>
#include <gcrypt.h>

#define KEY_SIZE 32            // 256-битный ключ
#define SALT_SIZE 32           // Размер криптографической соли
#define DATA_BLOCK 512         // Размер блока данных
#define COUNT_SIZE 4           // 32-битный счетчик
#define HASH_ALGO GCRY_MD_STRIBOG256
#define CIPHER_ALGO GCRY_CIPHER_GOST28147

typedef struct {
    unsigned char* context_tag;
    size_t tag_length;
    unsigned char* user_ctx;
    size_t user_ctx_len;
    unsigned char* aux_data;
    size_t aux_data_len;
    size_t output_bits;
    unsigned char salt[SALT_SIZE];
    uint8_t counter[6];  // Добавляем недостающий член
} KeyGenCtx;

// Генерация базового ключа
void create_base_key(
    const unsigned char* root_key,
    size_t key_len,
    const unsigned char* salt_data,
    unsigned char* base_key
);

// Формирование блока параметров
void prepare_block(
    const unsigned char* prev_state,
    const unsigned char* counter,
    const KeyGenCtx* ctx,
    unsigned char* output
);

// Итеративная генерация ключевого материала
void expand_key_material(
    const unsigned char* base_key,
    const KeyGenCtx* ctx,
    unsigned char* result
);

// Инициализация контекста генерации ключей
void init_keygen(
    unsigned char* root_key,
    size_t key_size,
    KeyGenCtx* ctx
);

// Пакетная генерация ключей
void bulk_keygen(
    unsigned char* master_key,
    size_t key_size,
    size_t key_quantity,
    KeyGenCtx* ctx,
    int verbose_mode
);

#endif // KEYGEN_H