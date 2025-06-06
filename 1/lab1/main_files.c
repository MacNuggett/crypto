#include "src/files.h"
#include "src/omac.h"


static unsigned char test_key[32] = {
    0xff, 0xfe, 0xfd, 0xfc,
    0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4,
    0xf3, 0xf2, 0xf1, 0xf0,
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};

// static unsigned char
// encrypt_test_string[32] =
// {
//     0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89,
//     0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
//     0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
//     0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92
// };

// static unsigned char
// decrypt_test_string_ECB[32] =
// {
//     0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c,
//     0x1e, 0xbc, 0xcf, 0xea, 0xe9, 0xd9, 0xd8, 0x11,
//     0x48, 0x6e, 0x55, 0xd3, 0x15, 0xe7, 0x70, 0xde,
//     0xa0, 0x72, 0xf3, 0x94, 0x04, 0x3f, 0x07, 0x2b
// };

static unsigned char
init_vect_ctr_string[BLCK_SIZE / 2] =
{
    0x78, 0x56, 0x34, 0x12
};

// static void
// print_cipher_blck(uint8_t *state, uint64_t size)
// {
//     unsigned int i;
//     for (i = 0; i < size; i++)
//         printf("%02x", state[i]);
//     printf("\n");
// }

// const char *in_file_name = "test_magma.txt";
// const char *out_file_ECB_name = "encrypt_test_ECB.txt";
// const char *out_file_CTR_name = "encrypt_test_CTR.txt";

const char *in_file_1mb_name = "test/1mb.bin";
const char *in_file_100mb_name = "test/100mb.bin";
const char *in_file_1gb_name = "test/1gb.bin";

const char *out_file_CTR_name = "test_magma_100bm.bin";

void print_usage() {
  printf("Usage:\n");
  printf("./program <type>\n\n");
  printf("Available options:\n");
  printf("1 - Process 1MB file (1mb.bin -> 1mb_result.bin)\n");
  printf("2 - Process 100MB file (100mb.bin -> 100mb_result.bin)\n");
  printf("3 - Process 1GB file (1gb.bin -> 1gb_result.bin)\n\n");
  printf("Example: ./program 1\n");
}

int file_exists(const char *filename) {
  FILE *file = fopen(filename, "rb");
  if (file) {
      fclose(file);
      return 1;
  }
  return 0;
}

int process_file(const char *input, const char *output) {
  FILE *in_file = fopen(input, "rb");
  if (in_file == NULL)
  {
      printf("Error opening file: %s\n", input);
      return -1;
  }

  FILE *out_file = fopen(output, "wb");
  if (out_file == NULL)
  {
      printf("Error opening file: %s\n", output);
      return -1;
  }
  CTR_Crypt_File(in_file, out_file, init_vect_ctr_string, test_key, get_size_file(in_file));
  printf("Operation completed. Output: %s\n\n", output);
  
  uint8_t mac[BLOCK_SIZE];
  if (OMAC_File(output, mac) != 0) {
      return 1;
  }

  printf("MAC: ");
  for (int i = 0; i < BLOCK_SIZE; i++) {
      printf("%02X", mac[i]);
  }
  printf("\n");
}
// const char *out_file_ECB_name = "encrypt_test_ECB.txt";
// in_file_name
int main(int argc, char *argv[])
{
    // uint8_t out_buf[BLCK_SIZE];
    // ECB_Encrypt(encrypt_test_string, out_buf, test_key, 32);
    // printf("Text:\n");
    // print_cipher_blck(encrypt_test_string, 32);
    // printf("ECB encrypted  text:\n");
    // print_cipher_blck(out_buf, 32);

    // ECB_Decrypt(decrypt_test_string_ECB, out_buf, test_key, 32);
    // printf("ECB cipher text:\n");
    // print_cipher_blck(decrypt_test_string_ECB, 32);
    // printf("ECB decrypted  text:\n");
    // print_cipher_blck(out_buf, 32);

    // FILE *in_file_1mb = fopen(in_file_1mb_name, "rb");
    // if (in_file_1mb == NULL)
    // {
    //     printf("Error opening file: %s\n", in_file_1mb_name);
    //     return -1;
    // }

    // FILE *in_file_100mb = fopen(in_file_100mb_name, "rb");
    // if (in_file_100mb == NULL)
    // {
    //     printf("Error opening file: %s\n", in_file_100mb_name);
    //     return -1;
    // }

    // FILE *in_file_1gb = fopen(in_file_1gb_name, "rb");
    // if (in_file_1gb == NULL)
    // {
    //     printf("Error opening file: %s\n", in_file_1gb_name);
    //     return -1;
    // }

    // FILE *out_file_ECB = fopen(out_file_ECB_name, "wb");
    // if (out_file_ECB == NULL)
    // {
    //     printf("Error opening file: %s\n", out_file_ECB_name);
    //     return -1;
    // }
    
    // FILE *out_file_CTR = fopen(out_file_CTR_name, "wb");
    // if (out_file_CTR == NULL)
    // {
    //     printf("Error opening file: %s\n", out_file_CTR_name);
    //     return -1;
    // }
    // CTR_Crypt_File(in_file_100mb, out_file_CTR, init_vect_ctr_string, test_key, get_size_file(in_file_100mb));

    // CTR_Crypt_File(in_file, out_file_CTR, init_vect_ctr_string, test_key, get_size_file(in_file));
    // ECB_Encrypt_File(in_file, out_file_ECB, test_key, get_size_file(in_file), PAD_MODE_1);
    // fclose(out_file_ECB);
    

      print_usage();
      if (argc != 2) {
        print_usage();
        return EXIT_FAILURE;
    }

    int choice = atoi(argv[1]);

      switch(choice) {
          case 1:
              process_file("1mb.bin", "1mb_result.bin");
              break;
          case 2:
              process_file("100mb.bin", "100mb_result.bin");
              break;
          case 3:
              process_file("1gb.bin", "1gb_result.bin");
              break;
          case 0:
              printf("Exiting...\n");
              return 0;
          default:
              printf("Invalid choice! Try again.\n");
      }


    // fclose(in_file_100mb);
    // fclose(out_file_CTR);

    return 0;
}
