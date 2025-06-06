#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crisp.h"

#define MAX_FAILED_AUTH 5
#define BLOCK_DURATION 10 // seconds

static int failed_attempts = 0;
static time_t blocked_until = 0;

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

void generate_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) exit(1);
    fread(buf, 1, len, f);
    fclose(f);
}

//============================================
// Пример использования криптосистемы
//============================================
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


    // Инициализация контекста
    CRISP_Context ctx;
    uint8_t baseKey[32] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
                          0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
                          0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
                          0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};

    log_event("baseKey сгенерирован");
    uint8_t sourceId[16] = "CRISP_SOURCE_001";
    log_event("sourceId сгенерирован");
    uint8_t keyId[16] = "INIT_KEY_00001";
    log_event("keyId сгенерирован");

    crisp_init(&ctx, baseKey, sourceId, 16, keyId, 16, MGM_KDF_CMAC);

    // Создание тестового сообщения
    const char *original_text = "Secret message for GOST Magma encryption!";
    size_t text_len = strlen(original_text) + 1;

    CRISP_Message encrypted_msg;
    uint8_t *payload = (uint8_t*)malloc(text_len);
    memcpy(payload, original_text, text_len);

    if (!crisp_create_message(&ctx, payload, text_len, &encrypted_msg)) {
        fprintf(stderr, "Message creation failed!\n");
        return 1;
    }
    log_event("Сообщение зашифровано");

    // Вывод информации о сообщении
    printf("=== Encrypted Message ===\n");
    printf("SeqNum: %lu\n", encrypted_msg.seqNum);
    printf("MAC: ");
    for (int i = 0; i < 8; i++) printf("%02X", encrypted_msg.mac[i]);
    printf("\nPayload size: %zu bytes\n", encrypted_msg.payloadLen);

    // Обработка сообщения
    uint8_t decrypted[2048];
    size_t decrypted_len;

    if (!crisp_process_message(&ctx, &encrypted_msg, decrypted, &decrypted_len)) {
        fprintf(stderr, "Message processing failed!\n");
        return 1;
    }
    log_event("Сообщение расшифровано");

    // Вывод результатов
    printf("\n=== Decryption Results ===\n");
    printf("Original length: %zu\n", text_len);
    printf("Decrypted length: %zu\n", decrypted_len);
    printf("Decrypted text: %s\n", decrypted);
    printf("MAC verification: %s\n",
        memcmp(encrypted_msg.mac, encrypted_msg.mac, 8) ? "FAIL" : "OK");

    // Очистка памяти
    crisp_free_message(&encrypted_msg);
    log_event("Сообщение очищено");


    secure_zero(baseKey, 32);
    log_event("baseKey очищен");
    secure_zero(sourceId, 16);
    log_event("sourceId очищен");
    secure_zero(keyId, 16);
    log_event("keyId очищен");

    free(payload);

    return 0;
}

// Реализации функций из интеграционного кода
// (должны быть подключены через отдельные файлы)
