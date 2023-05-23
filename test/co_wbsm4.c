#include "test_local.h"
#include <wbcrypto/co_wbsm4.h>

#define TESTTIME 10

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

int test_co_wbsm4() {
    int ret = 0;
    unsigned char cipher[16] = {0};
    unsigned char plain1[16] = {0};
    unsigned char plain2[16] = {0};

    WBCRYPTO_co_wbsm4_enc_context *wbsm4_ctx_enc;
    WBCRYPTO_co_wbsm4_dec_context *wbsm4_ctx_dec;
    WBCRYPTO_co_wbsm4_dec_ee_context wbsm4_ctx_dec_ee;
    wbsm4_ctx_enc = WBCRYPTO_co_wbsm4_enc_context_init();
    wbsm4_ctx_dec = WBCRYPTO_co_wbsm4_dec_context_init();

    WBCRYPTO_co_wbsm4_gen_table(wbsm4_ctx_enc, wbsm4_ctx_dec, &wbsm4_ctx_dec_ee, key, sizeof(key));
    WBCRYPTO_co_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_co_wbsm4_decrypt(cipher, plain1, wbsm4_ctx_dec);
    TEST_print_state(plain1, sizeof(plain1));
    WBCRYPTO_co_wbsm4_ee_decrypt(plain1, plain2, &wbsm4_ctx_dec_ee);
    TEST_print_state(plain2, sizeof(plain2));
    ret = 1;
cleanup:
    WBCRYPTO_co_wbsm4_enc_context_free(wbsm4_ctx_enc);
    WBCRYPTO_co_wbsm4_dec_context_free(wbsm4_ctx_dec);
    return ret;
}

int test_co_wbsm4_with_file() {
    int ret = 0;
    unsigned char cipher[16] = {0};
    unsigned char plain1[16] = {0};
    unsigned char plain2[16] = {0};

    WBCRYPTO_co_wbsm4_enc_context *wbsm4_ctx_enc;
    WBCRYPTO_co_wbsm4_dec_context *wbsm4_ctx_dec;
    WBCRYPTO_co_wbsm4_dec_ee_context wbsm4_ctx_dec_ee;
    wbsm4_ctx_enc = WBCRYPTO_co_wbsm4_enc_context_init();
    wbsm4_ctx_dec = WBCRYPTO_co_wbsm4_dec_context_init();

    WBCRYPTO_co_wbsm4_gen_table(wbsm4_ctx_enc, wbsm4_ctx_dec, &wbsm4_ctx_dec_ee, key, sizeof(key));
    WBCRYPTO_co_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_co_wbsm4_decrypt(cipher, plain1, wbsm4_ctx_dec);
    TEST_print_state(plain1, sizeof(plain1));
    WBCRYPTO_co_wbsm4_ee_decrypt(plain1, plain2, &wbsm4_ctx_dec_ee);
    TEST_print_state(plain2, sizeof(plain2));
    ret = 1;
cleanup:
    WBCRYPTO_co_wbsm4_enc_context_free(wbsm4_ctx_enc);
    WBCRYPTO_co_wbsm4_dec_context_free(wbsm4_ctx_dec);
    return ret;
}

int test_co_wbsm4_perform() {
    int ret = 0, i;
    unsigned char cipher[16] = {0};
    unsigned char plain1[16] = {0};
    unsigned char plain2[16] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_co_wbsm4_enc_context *wbsm4_ctx_enc;
    WBCRYPTO_co_wbsm4_dec_context *wbsm4_ctx_dec;
    WBCRYPTO_co_wbsm4_dec_ee_context wbsm4_ctx_dec_ee;
    wbsm4_ctx_enc = WBCRYPTO_co_wbsm4_enc_context_init();
    wbsm4_ctx_dec = WBCRYPTO_co_wbsm4_dec_context_init();

    WBCRYPTO_co_wbsm4_gen_table(wbsm4_ctx_enc, wbsm4_ctx_dec, &wbsm4_ctx_dec_ee, key, sizeof(key));

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_co_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[CO-WBSM4 encrypt] Time cost: %lf s, it means that the encryption speed is: %f MBytes/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_co_wbsm4_decrypt(cipher, plain1, wbsm4_ctx_dec);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[CO-WBSM4 decrypt1] Time cost: %lf s, it means that the decryption speed is: %f MBytes/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_co_wbsm4_ee_decrypt(plain1, plain2, &wbsm4_ctx_dec_ee);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[CO-WBSM4 decrypt2] Time cost: %lf s, it means that the decryption speed is: %f MBytes/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));

    ret = 1;
cleanup:
    WBCRYPTO_co_wbsm4_enc_context_free(wbsm4_ctx_enc);
    WBCRYPTO_co_wbsm4_dec_context_free(wbsm4_ctx_dec);
    return ret;
}

int main() {
    test_co_wbsm4();
    test_co_wbsm4_with_file();
    test_co_wbsm4_perform();
}
