#include "test_local.h"
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/fpe_app.h>
#include <time.h>

#define TESTTIME 10000

int test_key_to_file() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "你好中国";
    char cipher[100] = {0};
    char plain[100] = {0};

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_wbsm4_key2file(wbsm4_ctx, "/home/xie/enc.whibox");

    WBCRYPTO_wbsm4_context *wbsm4_ctx2 = WBCRYPTO_wbsm4_context_init(1);
    WBCRYPTO_wbsm4_file2key(wbsm4_ctx2, "/home/xie/enc.whibox");

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, wbsm4_ctx2, WBCYRPTO_FPE_CIPHER_WBSM4, WBCYRPTO_FPE_FFX_FF1);
    WBCRYPTO_fpe_encrypt_cn_utf8(&app_ctx, input, cipher);
    printf("[FPE address] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_cn_utf8(&app_ctx, cipher, plain);
    printf("[FPE address] decrypt answer: %s\n", plain);
}

int test_key2file_perform() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "138****8888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_wbsm4_key2file(wbsm4_ctx, "/home/xie/enc.whibox");

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_wbsm4_context *wbsm4_ctx2 = WBCRYPTO_wbsm4_context_init(1);
        WBCRYPTO_wbsm4_file2key(wbsm4_ctx2, "/home/xie/enc.whibox");
        WBCRYPTO_fpe_app_context app_ctx;
        WBCRYPTO_fpe_app_init(&app_ctx, wbsm4_ctx, WBCYRPTO_FPE_CIPHER_WBSM4, WBCYRPTO_FPE_FFX_FF1);
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
}

int main() {
    test_key_to_file();
    test_key2file_perform();
}
