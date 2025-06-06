#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <stdint.h>

// Размер хеша для алгоритма Стрибог-256
#define GOST3411_256_DIGEST_SIZE 32

// Функция для вывода данных в шестнадцатеричном формате
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]); // Вывод каждого байта в формате HEX
    }
    printf("\n");
}

/**
 * Функция формирования производных ключей на основе алгоритма KDF_TREE_GOSTR3411_2012_256
 * 
 * @param K         Мастер-ключ
 * @param K_len     Длина мастер-ключа
 * @param label     Метка для формирования ключа
 * @param label_len Длина метки
 * @param seed      Дополнительные случайные данные (может быть NULL)
 * @param seed_len  Длина дополнительных данных
 * @param R         Количество итераций
 * @param L         Требуемая длина производного ключа
 * @param out       Буфер для результата
 * 
 * @return 0 в случае успеха, -1 при ошибке
 */
int KDF_TREE_GOSTR3411_2012_256(
    const uint8_t *K,
    size_t K_len,
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    uint32_t R,
    uint32_t L,
    uint8_t *out)
{
    // Проверка длины мастер-ключа
    if (K_len < 32) {
        fprintf(stderr, "Ошибка: мастер-ключ должен быть не менее 32 байт\n");
        return -1;
    }

    // Проверка максимальной длины выходного ключа
    if (L > 32 * (UINT32_MAX - 1)) {
        fprintf(stderr, "Ошибка: запрошенная длина ключа слишком велика\n");
        return -1;
    }

    // Инициализация контекста хеширования (Стрибог-256)
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_STRIBOG256, 0) != 0) {
        fprintf(stderr, "Ошибка: не удалось инициализировать алгоритм Стрибог-256\n");
        return -1;
    }

    // Копируем первые 32 байта мастер-ключа
    uint8_t K_1[GOST3411_256_DIGEST_SIZE];
    memcpy(K_1, K, GOST3411_256_DIGEST_SIZE);

    size_t bytes_copied = 0; // Счетчик скопированных байтов

    // Основной цикл формирования ключа
    for (uint32_t i = 1; i <= R && bytes_copied < L; i++) {
        // Буфер для входных данных хеш-функции
        uint8_t hash_input[4 + label_len + 1 + seed_len + 4];
        size_t pos = 0;
        
        // 4.1.1. Добавляем номер итерации (4 байта, big-endian)
        hash_input[pos++] = (i >> 24) & 0xFF;
        hash_input[pos++] = (i >> 16) & 0xFF;
        hash_input[pos++] = (i >> 8)  & 0xFF;
        hash_input[pos++] = i & 0xFF;
        
        // 4.1.2. Добавляем метку (label)
        memcpy(hash_input + pos, label, label_len);
        pos += label_len;
        
        // 4.1.3. Добавляем разделительный байт 0x00
        hash_input[pos++] = 0x00;
        
        // 4.1.4. Добавляем дополнительные случайные данные (seed), если указаны
        if (seed && seed_len > 0) {
            memcpy(hash_input + pos, seed, seed_len);
            pos += seed_len;
        }
        
        // 4.1.5. Добавляем длину ключа L (4 байта, big-endian)
        hash_input[pos++] = (L >> 24) & 0xFF;
        hash_input[pos++] = (L >> 16) & 0xFF;
        hash_input[pos++] = (L >> 8)  & 0xFF;
        hash_input[pos++] = L & 0xFF;

        // Вычисляем хеш: H(K_1 || data)
        gcry_md_reset(hd); // Сбрасываем состояние хеш-функции
        gcry_md_write(hd, K_1, GOST3411_256_DIGEST_SIZE); // Добавляем K_1
        gcry_md_write(hd, hash_input, pos); // Добавляем подготовленные данные

        // Получаем результат хеширования
        uint8_t *K_i = gcry_md_read(hd, GCRY_MD_STRIBOG256);
        if (!K_i) {
            fprintf(stderr, "Ошибка: не удалось вычислить хеш\n");
            gcry_md_close(hd);
            return -1;
        }

        // Копируем результат в выходной буфер
        size_t to_copy = (L - bytes_copied) < GOST3411_256_DIGEST_SIZE ?
                         (L - bytes_copied) : GOST3411_256_DIGEST_SIZE;
        memcpy(out + bytes_copied, K_i, to_copy);
        bytes_copied += to_copy;

        // Обновляем K_1 для следующей итерации
        memcpy(K_1, K_i, GOST3411_256_DIGEST_SIZE);
    }

    // Освобождаем ресурсы хеш-функции
    gcry_md_close(hd);
    return 0;
}