#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/fpe.h>
#include <time.h>

#define TESTTIME 1

int test_sm4_fpe() {
    int i;

    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 12);
    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF1] [sm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [sm4] decrypt answer: %s\n", plain);

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF3] [sm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [sm4] decrypt answer: %s\n", plain);
}

int test_wbsm4_fpe() {
    int i;

    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF1] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [wbsm4] decrypt answer: %s\n", plain);

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF3] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [wbsm4] decrypt answer: %s\n", plain);
}

int main() {
    test_sm4_fpe();
    test_wbsm4_fpe();
}
