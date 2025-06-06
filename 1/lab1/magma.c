#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../perf_metrics/perf_metrics.h"

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

// Константы для алгоритма Магма
#define BLOCK_SIZE 8  // Размер блока в байтах (64 бита)
#define KEY_SIZE 32   // Размер ключа в байтах (256 бит)
#define ROUNDS 32     // Количество раундов шифрования

// S-блоки согласно ГОСТ 34.12-2015
const uint8_t s_box[8][16] = {
    {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
    {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
    {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
    {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
    {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
    {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
    {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
};

// Функция замены по S-блокам
void s_transform(uint32_t *a) {
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (*a >> (4 * i)) & 0xF;  // Извлекаем 4-битный фрагмент
        nibble = s_box[i][nibble];               // Заменяем по S-блоку
        result |= (nibble << (4 * i));           // Собираем результат
    }
    *a = result;
}

// Циклический сдвиг влево на 11 бит
uint32_t left_shift11(uint32_t a) {
    return (a << 11) | (a >> (32 - 11));
}

// Один раунд шифрования
void round(uint32_t *a, uint32_t k) {
    uint32_t temp = *a + k;  // Сложение с ключом раунда
    s_transform(&temp);      // Применение S-блоков
    temp = left_shift11(temp); // Циклический сдвиг
    *a ^= temp;              // XOR с результатом
}

// Генерация раундовых ключей
void key_schedule(const uint8_t *key, uint32_t *round_keys) {
    // Первые 8 ключей - части исходного ключа
    for (int i = 0; i < 8; i++) {
        round_keys[i] = *((uint32_t*)(key + 4 * i));
    }

    // Ключи с 8 по 31 - повторение первых 8 ключей в обратном порядке
    for (int i = 0; i < 24; i++) {
        round_keys[8 + i] = round_keys[i % 8];
    }

    // Последние 8 ключей - первые 8 в обратном порядке
    for (int i = 0; i < 8; i++) {
        round_keys[31 - i] = round_keys[i];
    }
}

// Шифрование одного блока
void magma_encrypt_block(const uint8_t *plain, uint8_t *cipher, const uint32_t *round_keys) {
    uint32_t a = *((uint32_t*)plain);      // Левая половина блока
    uint32_t b = *((uint32_t*)(plain + 4)); // Правая половина блока

    // 32 раунда шифрования
    for (int i = 0; i < ROUNDS; i++) {
        round(i < 24 ? &b : &a, round_keys[i]);
    }

    // Записываем результат
    *((uint32_t*)cipher) = a;
    *((uint32_t*)(cipher + 4)) = b;
}

// Режим OFB (Output Feedback)
void magma_ofb(const uint8_t *iv, const uint8_t *key, const uint8_t *input, uint8_t *output, size_t length) {
    uint32_t round_keys[ROUNDS];
    key_schedule(key, round_keys);  // Генерация ключей

    uint8_t feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);  // Инициализация вектором инициализации

    // Обработка данных блоками
    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t encrypted[BLOCK_SIZE];
        magma_encrypt_block(feedback, encrypted, round_keys);  // Шифруем feedback
        memcpy(feedback, encrypted, BLOCK_SIZE);  // Обновляем feedback

        // XOR входных данных с зашифрованным feedback
        size_t block_size = (length - i) < BLOCK_SIZE ? (length - i) : BLOCK_SIZE;
        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ encrypted[j];
        }
    }
}

// Тестирование производительности для файлов разного размера
void test_file_encryption(const char* filename, size_t file_size_mb) {
    printf("\n=== Тестирование файла %zu MB ===\n", file_size_mb);
    PerfMetrics metrics;

    // Создание буфера с тестовыми данными
    size_t buffer_size = file_size_mb * 1024 * 1024;
    uint8_t* buffer = malloc(buffer_size);

    // Заполнение буфера случайными данными
    for(size_t i = 0; i < buffer_size; i++) {
        buffer[i] = rand() % 256;
    }

    // Генерация случайного ключа и вектора инициализации
    uint8_t key[KEY_SIZE];
    uint8_t iv[BLOCK_SIZE];
    for(int i = 0; i < KEY_SIZE; i++) key[i] = rand() % 256;
    for(int i = 0; i < BLOCK_SIZE; i++) iv[i] = rand() % 256;

    // Замер времени шифрования
    clock_t start = clock();
    uint8_t* encrypted = malloc(buffer_size);
    magma_ofb(iv, key, buffer, encrypted, buffer_size);
    clock_t end = clock();

    double time_sec = (double)(end - start) / CLOCKS_PER_SEC;
    double speed_mbs = file_size_mb / time_sec;

    printf("Шифрование: %.2f сек (%.2f MB/сек)\n", time_sec, speed_mbs);

    start_measurement(&metrics);
    // Замер времени расшифрования
    start = clock();
    uint8_t* decrypted = malloc(buffer_size);
    magma_ofb(iv, key, encrypted, decrypted, buffer_size);
    end = clock();

    time_sec = (double)(end - start) / CLOCKS_PER_SEC;
    speed_mbs = file_size_mb / time_sec;

    printf("Расшифрование: %.2f сек (%.2f MB/сек)\n", time_sec, speed_mbs);

    // Проверка корректности расшифрования
    if(memcmp(buffer, decrypted, buffer_size)) {
        printf("Ошибка: данные не совпадают после расшифрования!\n");
    } else {
        printf("Проверка: данные совпадают после расшифрования\n");
    }
    stop_measurement(&metrics);

    free(buffer);
    free(encrypted);
    free(decrypted);
}

// Тестирование смены ключей
void test_key_rotation(size_t blocks_before_change) {
    printf("\n=== Тест смены ключа (каждые %zu блоков) ===\n", blocks_before_change);

    const size_t total_blocks = 1000000;  // Общее количество блоков для теста
    uint8_t* data = malloc(total_blocks * BLOCK_SIZE);
    uint8_t* encrypted = malloc(total_blocks * BLOCK_SIZE);

    // Генерация тестовых данных
    for(size_t i = 0; i < total_blocks * BLOCK_SIZE; i++) {
        data[i] = rand() % 256;
    }

    clock_t start = clock();

    size_t blocks_processed = 0;
    while(blocks_processed < total_blocks) {
        // Генерация нового ключа и IV
        uint8_t key[KEY_SIZE];
        uint8_t iv[BLOCK_SIZE];
        for(int i = 0; i < KEY_SIZE; i++) key[i] = rand() % 256;
        for(int i = 0; i < BLOCK_SIZE; i++) iv[i] = rand() % 256;

        // Обработка блоков между сменами ключа
        size_t blocks_to_process = (total_blocks - blocks_processed) > blocks_before_change ?
                                 blocks_before_change : (total_blocks - blocks_processed);

        magma_ofb(iv, key,
                 data + blocks_processed * BLOCK_SIZE,
                 encrypted + blocks_processed * BLOCK_SIZE,
                 blocks_to_process * BLOCK_SIZE);

        blocks_processed += blocks_to_process;
    }

    clock_t end = clock();

    double time_sec = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Обработано %zu блоков за %.2f сек\n", total_blocks, time_sec);
    printf("Скорость обработки: %.2f блоков/сек\n", total_blocks / time_sec);

    free(data);
    free(encrypted);
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

    printf("=== Тестирование алгоритма Магма в режиме OFB ===\n");

    // Генерация ключа и вектора инициализации
    uint8_t key[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) {
        key[i] = rand() % 256;
    }

    uint8_t iv[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = rand() % 256;
    }

    // Тестовое сообщение
    const char *plaintext = "Это тестовое сообщение для проверки реализации алгоритма Магма в режиме OFB.";
    size_t length = strlen(plaintext);

    // Выделение памяти для шифротекста и расшифрованного текста
    uint8_t *ciphertext = malloc(length);
    uint8_t *decrypted = malloc(length);

    printf("\n=== Базовый тест корректности ===\n");
    printf("Исходный текст: %s\n", plaintext);

    // Шифрование
    magma_ofb(iv, key, (uint8_t*)plaintext, ciphertext, length);
    printf("Шифрование выполнено\n");

    // Расшифрование (в OFB режиме шифрование и расшифрование одинаковы)
    magma_ofb(iv, key, ciphertext, decrypted, length);
    printf("Расшифрование выполнено\n");

    // Проверка корректности
    if (memcmp(plaintext, decrypted, length)) {
        printf("Ошибка: расшифрованный текст не совпадает с оригиналом!\n");
    } else {
        printf("Проверка пройдена: расшифрованный текст совпадает с оригиналом\n");
        printf("Расшифрованный текст: %s\n", decrypted);
    }

    // Тестирование производительности для разных размеров данных
    // printf("\n=== Тестирование производительности ===\n");
    // test_file_encryption("1MB", 1);
    // test_file_encryption("100MB", 100);
    // test_file_encryption("1000MB", 1000);
    //
    // // Тестирование смены ключей
    // printf("\n=== Тестирование смены ключей ===\n");
    // test_key_rotation(10);    // Смена каждые 10 блоков
    // test_key_rotation(100);   // Смена каждые 100 блоков
    // test_key_rotation(1000);  // Смена каждые 1000 блоков

    free(ciphertext);
    free(decrypted);

    secure_zero(iv, sizeof(iv));
    secure_zero(key, sizeof(key));

    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(decrypted, sizeof(decrypted));
    log_event("Закрытие файлов и завершение программы");

    printf("\n=== Тестирование завершено ===\n");
    return 0;
}
