#include "test_local.h"
#include <wbcrypto/fpe_app.h>
#include <time.h>

#define TESTTIME 1

int test_fpe_phone() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_fpe_idcard() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "40000000000000000X";
    const char sample[] = "4412**********1234";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_idcard(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE idcard] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE idcard] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_idcard(&app_ctx, cipher, plain);
    printf("[FPE idcard] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_idcard_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE idcard with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_idcard_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE idcard with sample] decrypt answer: %s\n", plain);
}

int test_fpe_cn_utf8() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "你好世界";
    const char sample[] = "你好**";
    char cipher[100] = {0};
    char plain[100] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_cn_utf8(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE CN-UTF8] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE CN-UTF8] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_cn_utf8(&app_ctx, cipher, plain);
    printf("[FPE CN-UTF8] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE CN-UTF8 with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE CN-UTF8 with sample] decrypt answer: %s\n", plain);
}

int test_fpe_name() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "谢南江";
    char cipher[100] = {0};
    char plain[100] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_name(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE name] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE name] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_name(&app_ctx, cipher, plain);
    printf("[FPE name] decrypt answer: %s\n", plain);
}

int main() {
    test_fpe_phone();
    test_fpe_idcard();
    test_fpe_name();
    test_fpe_cn_utf8();
}
