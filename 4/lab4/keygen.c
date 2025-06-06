#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include <gcrypt.h>

// Генерация базового ключа
void create_base_key(
    const unsigned char* root_key,
    size_t key_len,
    const unsigned char* salt_data,
    unsigned char* base_key
) {
    gcry_md_hd_t md_ctx;
    gcry_md_open(&md_ctx, HASH_ALGO, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(md_ctx, root_key, key_len);
    gcry_md_write(md_ctx, salt_data, SALT_SIZE);
    
    unsigned char* hmac = gcry_md_read(md_ctx, 0);
    memcpy(base_key, hmac, KEY_SIZE);
    gcry_md_close(md_ctx);
}

// Формирование блока параметров
void prepare_block(
    const unsigned char* prev_state,
    const unsigned char* counter,
    const KeyGenCtx* ctx,
    unsigned char* output
) {
    size_t pos = 0;
    
    // Контекстная метка (256 бит)
    memcpy(output + pos, ctx->context_tag, ctx->tag_length);
    pos += 32;

    // Идентификатор счетчика
    memcpy(output + pos, counter, COUNT_SIZE);
    pos += 4;

    // Состояние предыдущей итерации
    memcpy(output + pos, prev_state, KEY_SIZE);
    pos += 32;

    // Длина выходных данных
    u_int64_t bit_length = ctx->output_bits;
    memcpy(output + pos, &bit_length, 6);
    pos += 31;

    // Пользовательский контекст
    memcpy(output + pos, ctx->user_ctx, ctx->user_ctx_len);
    pos += 16;

    // Дополнительные параметры
    memcpy(output + pos, ctx->aux_data, ctx->aux_data_len);
}

// Итеративная генерация ключевого материала
void expand_key_material(
    const unsigned char* base_key,
    const KeyGenCtx* ctx,
    unsigned char* result
) {
    unsigned char state[KEY_SIZE] = {0};
    unsigned char count[COUNT_SIZE] = {0};
    unsigned char buffer[DATA_BLOCK];

    size_t segments = (ctx->output_bits + 255) / 256;
    
    for (size_t idx = 0; idx < segments; idx++) {
        u_int32_t val;
        memcpy(&val, count, COUNT_SIZE);
        val = htonl(ntohl(val) + 1);
        memcpy(count, &val, COUNT_SIZE);

        prepare_block(state, count, ctx, buffer);
        
        unsigned char tmp_key[KEY_SIZE];
        create_base_key(base_key, KEY_SIZE, buffer, tmp_key);
        
        memcpy(state, tmp_key, KEY_SIZE);
        memcpy(result + idx * KEY_SIZE, tmp_key, KEY_SIZE);
    }
}

void init_keygen(
    unsigned char* root_key,
    size_t key_size,
    KeyGenCtx* ctx
) {
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    unsigned char base[KEY_SIZE];
    gcry_randomize(ctx->salt, SALT_SIZE, GCRY_STRONG_RANDOM);
    
    create_base_key(root_key, key_size, ctx->salt, base);
    expand_key_material(base, ctx, ctx->salt); // Используем salt как временный буфер
}

void bulk_keygen(
    unsigned char* master_key,
    size_t key_size,
    size_t key_quantity,
    KeyGenCtx* ctx,
    int verbose_mode // Добавлен флаг verbose
) {
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    for (size_t i = 0; i < key_quantity; i++) {
        unsigned char output[KEY_SIZE * 2];
        init_keygen(master_key, key_size, ctx);
        
        // Вывод ключей если активирован флаг -v
        if(verbose_mode) {
            printf("Key #%zu: ", i+1);
            for(size_t j = 0; j < KEY_SIZE; j++) {
                printf("%02X", ctx->salt[j]); // Используем соль как временный буфер
                if((j+1) % 8 == 0) printf(" ");
            }
            printf("\n");
        }
    }
}