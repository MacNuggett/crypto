#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "src/files.h"
#include "src/omac.h"

#define MAX_FAILED_AUTH 5
#define BLOCK_DURATION 10 // seconds

static int failed_attempts = 0;
static time_t blocked_until = 0;

// Простейшая символьная аутентификация (заглушка)
int authenticate_user() {
  char password[32];
  printf("Введите пароль доступа: ");
  if (fgets(password, sizeof(password), stdin) == NULL) return 0;

  // Удаляем символ новой строки
  password[strcspn(password, "\n")] = '\0';

  // Заглушка — пароль "securepass"
  return strcmp(password, "securepass") == 0;
}

void log_event(const char *msg) {
  FILE *log = fopen("crypto_audit.log", "a");
  if (log) {
    time_t now = time(NULL);
    fprintf(log, "[%s] %s \n", ctime(&now), msg);
    fclose(log);
  }
}

void secure_zero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--) *p++ = 0;
}

extern void CTR_Crypt(uint8_t *init_vec, uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size);

void generate_random_data(uint8_t *buffer, uint64_t size) {
    for (uint64_t i = 0; i < size; ++i) {
        buffer[i] = rand() % 256;
    }
}

void increment_iv(uint8_t *iv, uint64_t increment) {
    uint64_t counter;
    memcpy(&counter, iv + 8, sizeof(counter));
    counter += increment;
    memcpy(iv + 8, &counter, sizeof(counter));
}

int main() {
    time_t now = time(NULL);

    if (now < blocked_until) {
      printf("Доступ временно заблокирован. Повторите позже.\n");
      exit(1);
    }

    if (!authenticate_user()) {
      failed_attempts++;
      log_event("Неуспешная попытка аутентификации");
      if (failed_attempts >= MAX_FAILED_AUTH) {
        blocked_until = time(NULL) + BLOCK_DURATION;
        log_event("Превышено количество попыток входа. Блокировка.");
      }
      printf("Ошибка аутентификации.\n");
      exit(1);
    }

    log_event("Успешная аутентификация пользователя");

    srand(time(NULL));

    const uint64_t num_blocks = 1000000;
    const uint32_t block_size = 16;
    const uint64_t data_size = num_blocks * block_size;

    uint8_t *plaintext = malloc(data_size);
    generate_random_data(plaintext, data_size);

    uint8_t initial_iv[16];
    generate_random_data(initial_iv, sizeof(initial_iv));
    log_event("Сгенерирован IV");

    uint32_t modes[] = {1000};
    const int num_modes = sizeof(modes) / sizeof(modes[0]);

    for (int m = 0; m < num_modes; ++m) {
        uint32_t blocks_per_segment = modes[m];
        uint32_t segment_size = blocks_per_segment * block_size;
        uint32_t num_segments = num_blocks / blocks_per_segment;

        if (num_blocks % blocks_per_segment != 0) {
            fprintf(stderr, "Error: Blocks must be divisible by segment size\n");
            exit(1);
        }

        uint8_t **keys = malloc(num_segments * sizeof(uint8_t *));
        for (uint32_t i = 0; i < num_segments; ++i) {
            keys[i] = malloc(block_size);
            generate_random_data(keys[i], block_size);
        }
        log_event("Сгенерированы ключи");

        uint8_t *ciphertext = malloc(data_size);
        uint8_t *decrypted = malloc(data_size);

        for (uint32_t i = 0; i < num_segments; ++i) {
            uint8_t segment_iv[16];
            memcpy(segment_iv, initial_iv, 16);
            increment_iv(segment_iv, i * blocks_per_segment);

            uint8_t *in = plaintext + i * segment_size;
            uint8_t *out = ciphertext + i * segment_size;
            CTR_Crypt(segment_iv, in, out, keys[i], segment_size);
        }

        for (uint32_t i = 0; i < num_segments; ++i) {
            uint8_t segment_iv[16];
            memcpy(segment_iv, initial_iv, 16);
            increment_iv(segment_iv, i * blocks_per_segment);

            uint8_t *in = ciphertext + i * segment_size;
            uint8_t *out = decrypted + i * segment_size;
            CTR_Crypt(segment_iv, in, out, keys[i], segment_size);
        }

        if (memcmp(plaintext, decrypted, data_size) == 0) {
            printf("Key change every %d blocks: Success\n", blocks_per_segment);
        } else {
            printf("Key change every %d blocks: Failure\n", blocks_per_segment);
        }



        for (uint32_t i = 0; i < num_segments; ++i) free(keys[i]);

        log_event("Очищены ключи и расшифрованные данные");

        secure_zero(keys, sizeof(keys));
        secure_zero(ciphertext, sizeof(ciphertext));
        secure_zero(decrypted, sizeof(decrypted));

        free(keys);
        free(ciphertext);
        free(decrypted);
    }

    secure_zero(initial_iv, sizeof(initial_iv));
    log_event("Закрытие файлов и завершение программы");

    free(plaintext);
    return 0;
}
