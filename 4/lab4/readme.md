gcc -o crisp_protocol main.c magma_calc.c modes.c files.c keygen.c crisp.c -lgcrypt

gcc -o speed_test speed_test.c magma_calc.c modes.c files.c keygen.c crisp.c -lgcrypt
