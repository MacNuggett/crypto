#ifndef CRISP_H
#define CRISP_H

#include <stdint.h>
#include <stdlib.h>

#define CRISP_VERSION 0
#define MAX_MSG_SIZE 2048
#define WINDOW_SIZE 256
#define MAC_LENGTH 8
#define BLCK_SIZE 8
#define CYPHER_MODE_ENCRYPT 1
#define CYPHER_MODE_DECRYPT 0
#define SALT_SIZE 32

typedef enum {
    MGM_KDF_CMAC,
    GOST_CRISP_MODE
} CRISP_CryptoSet;

typedef struct {
    uint8_t baseKey[32];
    uint8_t sourceIdentifier[32];
    size_t sourceIdLen;
    uint8_t keyId[128];
    size_t keyIdLen;
    uint64_t nextSeqNum;
    uint64_t windowMin;
    uint64_t windowMax;
    uint8_t window[WINDOW_SIZE];
    CRISP_CryptoSet currentCS;
    uint8_t salt[SALT_SIZE];
} CRISP_Context;

typedef struct {
    uint8_t externalKeyIdFlag;
    uint8_t version;
    CRISP_CryptoSet cs;
    uint8_t *keyId;
    size_t keyIdLen;
    uint64_t seqNum;
    size_t payloadLen;
    uint8_t *payloadData;
    uint8_t mac[MAC_LENGTH];
} CRISP_Message;

// Прототипы функций
void crisp_init(CRISP_Context *ctx, const uint8_t *baseKey, const uint8_t *sourceId, size_t sourceIdLen, const uint8_t *keyId, size_t keyIdLen, CRISP_CryptoSet cs);
int crisp_create_message(CRISP_Context *ctx, const uint8_t *payload, size_t payloadLen, CRISP_Message *msg);
int crisp_process_message(CRISP_Context *ctx, const CRISP_Message *msg, uint8_t *payload, size_t *payloadLen);
void crisp_free_message(CRISP_Message *msg);

#endif // CRISP_H