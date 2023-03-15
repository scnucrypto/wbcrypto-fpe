#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>

int WBCRYPTO_fpe_app_init(WBCRYPTO_fpe_app_context *ctx, const uint8_t *key, size_t keylen, char *cipher, char *ffx) {
    int ret = 0;
    ctx->cipher = cipher;
    ctx->ffx = ffx;
    keylen = keylen >= 16 ? 16 : keylen;
    uint8_t input_key[16];
    memcpy(input_key, key, keylen);
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
        WBCRYPTO_sm4_init_key(sm4_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = sm4_ctx;
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1, 1);
        WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = wbsm4_ctx;
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
        WBCRYPTO_aes_init_key(aes_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = aes_ctx;
    } else {
        // default: aes
        WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
        WBCRYPTO_aes_init_key(aes_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = aes_ctx;
    }
    ret = 1;
cleanup:
    return ret;
}