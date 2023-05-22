#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>

int WBCRYPTO_fpe_app_init(WBCRYPTO_fpe_app_context *ctx, void *cipher_ctx, char *cipher, char *ffx) {
    ctx->cipher = cipher;
    ctx->ffx = ffx;
    ctx->cipher_ctx = cipher_ctx;
    return 1;
}