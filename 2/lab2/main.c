#include "kdf_tree.h"
#include "../perf_metrics/perf_metrics.h"
#include <time.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

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

// Функция для генерации случайных байтов
void generate_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;  // Генерация случайного байта
    }
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

    srand(time(NULL));  // Инициализация генератора случайных чисел

    printf("=== Тестирование функции KDF_TREE_GOSTR3411_2012_256 ===\n");

    // 1. Тестовый пример с фиксированным ключом
    printf("\n1. Тест с фиксированным мастер-ключом:\n");
    {
        int L = 64;  // Длина производного ключа в байтах
        // Фиксированный мастер-ключ для тестирования
        uint8_t master_key[32] = {
            0xc9, 0x7a, 0x61, 0x61, 0x2e, 0x82, 0x49, 0x28,
            0x4f, 0x01, 0x80, 0xa4, 0x81, 0xfa, 0xe5, 0x22,
            0xa8, 0xfb, 0xdd, 0x5b, 0x2f, 0xba, 0x6a, 0x7b,
            0xb9, 0xc9, 0xbf, 0xef, 0xe6, 0x63, 0xa6, 0xaf
        };

        const char *label = "test_label";  // Метка для KDF
        const char *seed = "test_seed";    // Соль для KDF
        uint8_t derived_key[L];           // Буфер для производного ключа

        // Вызов функции формирования ключа
        KDF_TREE_GOSTR3411_2012_256(
            master_key, sizeof(master_key),     // Мастер-ключ
            (const uint8_t *)label, strlen(label),  // Метка
            (const uint8_t *)seed, strlen(seed),    // Соль
            1,                              // Номер итерации
            L,                              // Длина производного ключа
            derived_key);                   // Выходной буфер

        // Вывод результатов
        print_hex("Мастер-ключ", master_key, sizeof(master_key));
        print_hex("Производный ключ", derived_key, sizeof(derived_key));

        secure_zero(label, sizeof(label));
        secure_zero(seed, sizeof(seed));
        secure_zero(derived_key, sizeof(derived_key));
        log_event("Завершение программы и очистка данных");
    }

    // // 2. Тестирование производительности
    // printf("\n2. Тестирование производительности:\n");
    // {
    //     PerfMetrics metrics;  // Структура для замера производительности
    //
    //     uint8_t master_key[32];      // Буфер для мастер-ключа
    //     uint8_t derived_key[32];     // Буфер для производного ключа
    //     // Различные размеры тестовых наборов
    //     const size_t test_sizes[] = {10000, 100000, 1000000};
    //     const size_t num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    //
    //     // Генерация случайного мастер-ключа
    //     generate_random_bytes(master_key, sizeof(master_key));
    //
    //     printf("Начало замера производительности...\n");
    //     start_measurement(&metrics);
    //
    //     for (size_t t = 0; t < num_tests; t++) {
    //         size_t n = test_sizes[t];  // Количество итераций для текущего теста
    //         printf("Тест %zu: %zu итераций...\n", t+1, n);
    //         clock_t start = clock();
    //
    //         for (size_t i = 0; i < n; i++) {
    //             // Формирование уникальной метки для каждой итерации
    //             char dynamic_label[32];
    //             snprintf(dynamic_label, sizeof(dynamic_label), "key_%zu", i);
    //
    //             // Вызов функции формирования ключа
    //             KDF_TREE_GOSTR3411_2012_256(
    //                 master_key, sizeof(master_key),
    //                 (const uint8_t *)dynamic_label, strlen(dynamic_label),
    //                 NULL, 0,  // Без использования соли
    //                 1,        // Номер итерации
    //                 32,       // Длина ключа (32 байта)
    //                 derived_key);
    //         }
    //
    //         double duration = (double)(clock() - start) / CLOCKS_PER_SEC;
    //         printf("Завершено за %.2f секунд (%.2f итераций/сек)\n",
    //               duration, n / duration);
    //     }
    //
    //     stop_measurement(&metrics);
    //     printf("Тестирование производительности завершено.\n");
    // }

    printf("\n=== Все тесты успешно завершены ===\n");
    return 0;
}
