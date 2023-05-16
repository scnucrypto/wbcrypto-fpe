#include "test_local.h"
#include <wbcrypto/co_wbsm4.h>

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

int main() {
    test_co_wbsm4();
    test_co_wbsm4_with_file();
}
