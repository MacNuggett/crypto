#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "crisp.h"

// 6.1. Тест скорости процедур аутентификации
void test_auth_speed() {
    struct timeval start, end;
    CRISP_Context ctx;
    uint8_t baseKey[32] = {0};
    uint8_t sourceId[16] = "TEST_SOURCE";
    uint8_t keyId[16] = "TEST_KEY_0001";
    
    crisp_init(&ctx, baseKey, sourceId, 12, keyId, 12, MGM_KDF_CMAC);

    // Генерация случайного количества итераций (10K - 1M)
    srand(time(NULL));
    int iterations = 10000 + rand() % 990001;

    printf("\n=== Authentication Speed Test ===\n");
    printf("Iterations: %d\n", iterations);

    gettimeofday(&start, NULL);
    
    for (int i = 0; i < iterations; i++) {
        CRISP_Message msg;
        uint8_t payload[64] = {0};
        crisp_create_message(&ctx, payload, sizeof(payload), &msg);
        crisp_free_message(&msg);
    }

    gettimeofday(&end, NULL);
    
    long seconds = end.tv_sec - start.tv_sec;
    long micros = ((seconds * 1000000) + end.tv_usec) - start.tv_usec;
    double avg_time = (double)micros / iterations;

    printf("Total time: %.2f sec\n", (double)micros/1000000);
    printf("Avg time per auth: %.3f μs\n", avg_time);
}

// 6.2. Тест сеансов обмена с аутентификацией и сменой ключей
void test_session_speed() {
    struct timeval start, end;
    CRISP_Context ctx;
    uint8_t baseKey[32] = {0};
    uint8_t sourceId[16] = "TEST_SOURCE";
    uint8_t keyId[16] = "TEST_KEY_0001";

    crisp_init(&ctx, baseKey, sourceId, 12, keyId, 12, MGM_KDF_CMAC);

    // Генерация случайного количества сеансов (100-1000)
    srand(time(NULL));
    int sessions = 100 + rand() % 901;
    int msg_per_session = 10; // Сообщений на сеанс

    printf("\n=== Session Speed Test ===\n");
    printf("Sessions: %d\n", sessions);
    printf("Messages per session: %d\n", msg_per_session);

    gettimeofday(&start, NULL);

    for (int s = 0; s < sessions; s++) {
        // Смена ключа (имитация)
        crisp_init(&ctx, baseKey, sourceId, 12, keyId, 12, MGM_KDF_CMAC);
        
        for (int m = 0; m < msg_per_session; m++) {
            CRISP_Message msg;
            uint8_t payload[256];
            size_t decrypted_len;
            uint8_t decrypted[256];
            
            // Генерация случайного payload
            for (int i = 0; i < sizeof(payload); i++) 
                payload[i] = rand() % 256;

            crisp_create_message(&ctx, payload, sizeof(payload), &msg);
            crisp_process_message(&ctx, &msg, decrypted, &decrypted_len);
            crisp_free_message(&msg);
        }
    }

    gettimeofday(&end, NULL);
    
    long seconds = end.tv_sec - start.tv_sec;
    long micros = ((seconds * 1000000) + end.tv_usec) - start.tv_usec;
    double avg_time = (double)micros / (sessions * msg_per_session);

    printf("Total time: %.2f sec\n", (double)micros/1000000);
    printf("Avg time per message: %.3f μs\n", avg_time);
}

int main() {
    // Запуск тестов
    test_auth_speed();
    test_session_speed();
    return 0;
}