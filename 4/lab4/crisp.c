#include "crisp.h"
#include "files.h"
#include "magma_calc.h"
#include "omac.h"
#include "keygen.h"
#include <stdio.h>
#include <string.h>

// Генерация подключей K1 и K2 для OMAC
void generate_omac_subkeys(const uint8_t *L, uint8_t *K1, uint8_t *K2) {
    const uint8_t Rb = 0x1B;
    uint8_t carry = (L[0] & 0x80) >> 7;
    memcpy(K1, L, BLOCK_SIZE);
    left_shift_block(K1);
    if (carry) K1[BLOCK_SIZE - 1] ^= Rb;

    carry = (K1[0] & 0x80) >> 7;
    memcpy(K2, K1, BLOCK_SIZE);
    left_shift_block(K2);
    if (carry) K2[BLOCK_SIZE - 1] ^= Rb;
}

// Сдвиг блока влево на 1 бит
void left_shift_block(uint8_t *block) {
    uint8_t carry = 0;
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        uint8_t next_carry = (block[i] & 0x80) >> 7;
        block[i] = (block[i] << 1) | carry;
        carry = next_carry;
    }
}

// XOR двух блоков
void xor_block(const uint8_t *a, const uint8_t *b, uint8_t *result) {
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// Инициализация контекста
void crisp_init(CRISP_Context *ctx, const uint8_t *baseKey, const uint8_t *sourceId, size_t sourceIdLen, const uint8_t *keyId, size_t keyIdLen, CRISP_CryptoSet cs) {
    if (sourceIdLen < 4 || sourceIdLen > 32) exit(1);
    memcpy(ctx->baseKey, baseKey, 32);
    memcpy(ctx->sourceIdentifier, sourceId, sourceIdLen);
    ctx->sourceIdLen = sourceIdLen;
    if (keyIdLen > 128) exit(1);
    memcpy(ctx->keyId, keyId, keyIdLen);
    ctx->keyIdLen = keyIdLen;
    ctx->nextSeqNum = 0;
    ctx->windowMin = 0;
    ctx->windowMax = 0;
    memset(ctx->window, 0, WINDOW_SIZE);
    ctx->currentCS = cs;
    memset(ctx->salt, 0, SALT_SIZE);
    memcpy(ctx->salt, sourceId, sourceIdLen < SALT_SIZE ? sourceIdLen : SALT_SIZE);
}

// Генерация ключей kMac и kEnc
void crisp_derive_keys(CRISP_Context *ctx, uint64_t seqNum, uint8_t *kMac, uint8_t *kEnc) {
    KeyGenCtx keyCtx = {0};
    keyCtx.output_bits = 256;
    memcpy(keyCtx.salt, ctx->salt, SALT_SIZE);  // Копирование данных

    // Преобразование seqNum в counter (6 байт)
    uint8_t counter[6] = {
        (uint8_t)(seqNum >> 40),
        (uint8_t)(seqNum >> 32),
        (uint8_t)(seqNum >> 24),
        (uint8_t)(seqNum >> 16),
        (uint8_t)(seqNum >> 8),
        (uint8_t)(seqNum & 0xFF)
    };
    memcpy(keyCtx.counter, counter, 6);

    init_keygen(ctx->baseKey, 32, &keyCtx);
    expand_key_material(ctx->baseKey, &keyCtx, kMac);
    expand_key_material(kMac, &keyCtx, kEnc);
}

// Вычисление MAC через OMAC
void compute_mac(const uint8_t *key, const uint8_t *data, size_t dataLen, uint8_t *mac) {
    uint8_t tmp_mac[BLOCK_SIZE];
    OMAC_File_data(data, dataLen, key, tmp_mac);
    memcpy(mac, tmp_mac, MAC_LENGTH);
}

// OMAC для буфера данных
int OMAC_File_data(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *mac) {
    GOST_Magma_Expand_Key(key);
    uint8_t L[BLOCK_SIZE] = {0};
    uint8_t K1[BLOCK_SIZE], K2[BLOCK_SIZE];
    GOST_Magma_Encrypt(L, L);
    generate_omac_subkeys(L, K1, K2);

    uint8_t T[BLOCK_SIZE] = {0};
    size_t blocks = len / BLOCK_SIZE;

    // Обработка полных блоков
    for (size_t i = 0; i < blocks; i++) {
        xor_block(T, data + i * BLOCK_SIZE, T);
        GOST_Magma_Encrypt(T, T);
    }

    // Обработка последнего блока
    size_t remaining = len % BLOCK_SIZE;
    if (remaining > 0 || blocks == 0) {
        uint8_t pad[BLOCK_SIZE] = {0};
        memcpy(pad, data + blocks * BLOCK_SIZE, remaining);
        pad[remaining] = 0x80; // ГОСТ-паддинг
        xor_block(pad, K2, pad);
        xor_block(T, pad, T);
        GOST_Magma_Encrypt(T, T);
    } else {
        xor_block(T, K1, T);
        GOST_Magma_Encrypt(T, T);
    }

    memcpy(mac, T, MAC_LENGTH);
    return 0;
}

// Шифрование/дешифрование ECB
void encrypt_decrypt_wrapper(uint8_t *key, uint8_t *data, size_t dataLen, uint8_t mode) {
    uint8_t *out_buf = malloc(dataLen);
    if (mode == CYPHER_MODE_ENCRYPT) {
        ECB_Encrypt(data, out_buf, key, dataLen);
    } else {
        ECB_Decrypt(data, out_buf, key, dataLen);
    }
    memcpy(data, out_buf, dataLen);
    free(out_buf);
}

// Создание сообщения
int crisp_create_message(CRISP_Context *ctx, const uint8_t *payload, size_t payloadLen, CRISP_Message *msg) {
    if (payloadLen > MAX_MSG_SIZE - 64) return 0;

    msg->externalKeyIdFlag = 1;
    msg->version = CRISP_VERSION;
    msg->cs = ctx->currentCS;
    msg->keyIdLen = ctx->keyIdLen;
    msg->keyId = malloc(msg->keyIdLen);
    memcpy(msg->keyId, ctx->keyId, msg->keyIdLen);
    msg->seqNum = ctx->nextSeqNum++;
    msg->payloadLen = payloadLen;
    msg->payloadData = malloc(payloadLen);
    memcpy(msg->payloadData, payload, payloadLen);

    // Шифрование
    uint8_t kMac[32], kEnc[32];
    crisp_derive_keys(ctx, msg->seqNum, kMac, kEnc);
    if (ctx->currentCS == MGM_KDF_CMAC) {
        encrypt_decrypt_wrapper(kEnc, msg->payloadData, msg->payloadLen, CYPHER_MODE_ENCRYPT);
    }

    // Формирование данных для MAC
    size_t macDataLen = 1 + 2 + 1 + msg->keyIdLen + 6 + msg->payloadLen;
    uint8_t *macData = malloc(macDataLen);
    size_t pos = 0;

    // Field1 (версия и флаги)
    uint16_t field1 = (msg->externalKeyIdFlag << 15) | msg->version;
    macData[pos++] = (field1 >> 8) & 0xFF;
    macData[pos++] = field1 & 0xFF;

    // CS
    macData[pos++] = msg->cs;

    // KeyID
    memcpy(macData + pos, msg->keyId, msg->keyIdLen);
    pos += msg->keyIdLen;

    // SeqNum (big-endian)
    macData[pos++] = (msg->seqNum >> 40) & 0xFF;
    macData[pos++] = (msg->seqNum >> 32) & 0xFF;
    macData[pos++] = (msg->seqNum >> 24) & 0xFF;
    macData[pos++] = (msg->seqNum >> 16) & 0xFF;
    macData[pos++] = (msg->seqNum >> 8) & 0xFF;
    macData[pos++] = msg->seqNum & 0xFF;

    // Payload
    memcpy(macData + pos, msg->payloadData, msg->payloadLen);

    // Вычисление MAC
    compute_mac(kMac, macData, macDataLen, msg->mac);
    free(macData);
    return 1;
}

// Обработка сообщения
int crisp_process_message(CRISP_Context *ctx, const CRISP_Message *msg, uint8_t *payload, size_t *payloadLen) {
    if (msg->version != CRISP_VERSION) return 0;
    if (msg->keyIdLen != ctx->keyIdLen || memcmp(msg->keyId, ctx->keyId, msg->keyIdLen) != 0) return 0;
    if (msg->seqNum < ctx->windowMin) return 0;
    if (msg->seqNum <= ctx->windowMax && ctx->window[msg->seqNum % WINDOW_SIZE]) return 0;

    // Генерация ключей
    uint8_t kMac[32], kEnc[32];
    crisp_derive_keys(ctx, msg->seqNum, kMac, kEnc);

    // Проверка MAC
    size_t macDataLen = 1 + 2 + 1 + msg->keyIdLen + 6 + msg->payloadLen;
    uint8_t *macData = malloc(macDataLen);
    size_t pos = 0;

    // Формирование macData (аналогично crisp_create_message)
    uint16_t field1 = (msg->externalKeyIdFlag << 15) | msg->version;
    macData[pos++] = (field1 >> 8) & 0xFF;
    macData[pos++] = field1 & 0xFF;
    macData[pos++] = msg->cs;
    memcpy(macData + pos, msg->keyId, msg->keyIdLen);
    pos += msg->keyIdLen;
    macData[pos++] = (msg->seqNum >> 40) & 0xFF;
    macData[pos++] = (msg->seqNum >> 32) & 0xFF;
    macData[pos++] = (msg->seqNum >> 24) & 0xFF;
    macData[pos++] = (msg->seqNum >> 16) & 0xFF;
    macData[pos++] = (msg->seqNum >> 8) & 0xFF;
    macData[pos++] = msg->seqNum & 0xFF;
    memcpy(macData + pos, msg->payloadData, msg->payloadLen);

    // Вычисление ожидаемого MAC
    uint8_t expectedMac[MAC_LENGTH];
    compute_mac(kMac, macData, macDataLen, expectedMac);
    free(macData);

    // Сравнение MAC
    if (memcmp(msg->mac, expectedMac, MAC_LENGTH) != 0) {
        return 0;
    }

    // Дешифрование
    if (msg->cs == MGM_KDF_CMAC) {
        uint8_t *tmp = malloc(msg->payloadLen);
        memcpy(tmp, msg->payloadData, msg->payloadLen);
        encrypt_decrypt_wrapper(kEnc, tmp, msg->payloadLen, CYPHER_MODE_DECRYPT);
        memcpy(payload, tmp, msg->payloadLen);
        *payloadLen = msg->payloadLen;
        free(tmp);
    } else {
        memcpy(payload, msg->payloadData, msg->payloadLen);
        *payloadLen = msg->payloadLen;
    }

    // Обновление окна
    if (msg->seqNum > ctx->windowMax) {
        ctx->windowMax = msg->seqNum;
        ctx->windowMin = (ctx->windowMax >= WINDOW_SIZE) ? ctx->windowMax - WINDOW_SIZE + 1 : 0;
    }
    ctx->window[msg->seqNum % WINDOW_SIZE] = 1;

    return 1;
}

// Освобождение памяти сообщения
void crisp_free_message(CRISP_Message *msg) {
    free(msg->keyId);
    free(msg->payloadData);
}