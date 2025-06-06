#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HASH_LEN 32 // SHA-256

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

typedef struct {
    unsigned char key[HASH_LEN];
    unsigned char value[HASH_LEN];
} HMAC_DRBG;

void hmac_drbg_update(HMAC_DRBG *drbg, const unsigned char *data, size_t data_len) {
    HMAC_CTX *ctx = HMAC_CTX_new();

    // Update key
    HMAC_Init_ex(ctx, drbg->key, HASH_LEN, EVP_sha256(), NULL);
    HMAC_Update(ctx, drbg->value, HASH_LEN);
    HMAC_Update(ctx, "\x00", 1);
    HMAC_Update(ctx, data, data_len);
    HMAC_Final(ctx, drbg->key, NULL);

    // Update value
    HMAC_Init_ex(ctx, drbg->key, HASH_LEN, EVP_sha256(), NULL);
    HMAC_Update(ctx, drbg->value, HASH_LEN);
    HMAC_Final(ctx, drbg->value, NULL);

    HMAC_CTX_free(ctx);
}

HMAC_DRBG *hmac_drbg_init(const unsigned char *entropy, size_t entropy_len,
                         const unsigned char *personalization, size_t personalization_len) {
    HMAC_DRBG *drbg = malloc(sizeof(HMAC_DRBG));
    if (!drbg) return NULL;

    // Initial values
    memset(drbg->key, 0x00, HASH_LEN);
    memset(drbg->value, 0x01, HASH_LEN);

    // Concatenate entropy and personalization
    unsigned char *seed = malloc(entropy_len + personalization_len);
    if (!seed) {
        free(drbg);
        return NULL;
    }

    memcpy(seed, entropy, entropy_len);
    memcpy(seed + entropy_len, personalization, personalization_len);

    hmac_drbg_update(drbg, seed, entropy_len + personalization_len);
    free(seed);

    return drbg;
}

void hmac_drbg_generate(HMAC_DRBG *drbg, unsigned char *output, size_t out_len) {
    size_t generated = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();

    while (generated < out_len) {
        HMAC_Init_ex(ctx, drbg->key, HASH_LEN, EVP_sha256(), NULL);
        HMAC_Update(ctx, drbg->value, HASH_LEN);
        HMAC_Final(ctx, drbg->value, NULL);

        size_t copy_len = (out_len - generated) > HASH_LEN ? HASH_LEN : (out_len - generated);
        memcpy(output + generated, drbg->value, copy_len);
        generated += copy_len;
    }

    hmac_drbg_update(drbg, NULL, 0);
    HMAC_CTX_free(ctx);
}

void hmac_drbg_free(HMAC_DRBG *drbg) {
    if (drbg) {
        memset(drbg->key, 0, HASH_LEN);
        memset(drbg->value, 0, HASH_LEN);
        free(drbg);
    }
}

void print_usage(const char *program_name) {
    printf("Usage: %s <output_file> <size_in_mb> [personalization_string]\n", program_name);
    printf("Example: %s random.bin 100\n", program_name);
}

int main(int argc, char *argv[]) {
    // Инициализация OpenSSL (для некоторых версий может потребоваться)
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

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    size_t mb_size = atoi(argv[2]);
    const char *personalization = (argc > 3) ? argv[3] : "";
    size_t data_size = mb_size * 1024 * 1024;

    // Generate entropy
    unsigned char entropy[48];
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        fprintf(stderr, "Error generating entropy\n");
        return 1;
    }
    log_event("Энтропия сгенерирована");

    // Initialize DRBG
    HMAC_DRBG *drbg = hmac_drbg_init(
        entropy, sizeof(entropy),
        (unsigned char*)personalization, strlen(personalization)
    );

    if (!drbg) {
        fprintf(stderr, "DRBG initialization failed\n");
        return 1;
    }

    // Generate data
    unsigned char *output = malloc(data_size);
    if (!output) {
        fprintf(stderr, "Memory allocation failed\n");
        hmac_drbg_free(drbg);
        return 1;
    }

    hmac_drbg_generate(drbg, output, data_size);

    // Save to file
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Could not open %s for writing\n", filename);
        free(output);
        hmac_drbg_free(drbg);
        return 1;
    }

    size_t written = fwrite(output, 1, data_size, fp);
    fclose(fp);

    if (written != data_size) {
        fprintf(stderr, "Write error: wrote %zu/%zu bytes\n", written, data_size);
        remove(filename);
    } else {
        printf("Successfully generated %zu MB to %s\n", mb_size, filename);
    }

    secure_zero(entropy, sizeof(entropy));
    log_event("Энтропия очищена");

    // Cleanup
    free(output);
    hmac_drbg_free(drbg);

    log_event("Завершение программы");

    return 0;
}
