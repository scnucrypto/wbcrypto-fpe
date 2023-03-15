#include <wbcrypto/fpe.h>
#include <stdint.h>
#include <string.h>

WBCRYPTO_fpe_context *WBCRYPTO_fpe_init(const uint8_t *tweak, size_t twklen, unsigned int radix,
                                        void *cipher_ctx, block128_f block) {
    struct fpe_ctx *ctx = malloc(sizeof(struct fpe_ctx));
    if (!ctx) {
        goto cleanup;
    }
    if (radix < 2 || radix > 36) {
        goto cleanup;
    }

    ctx->cipher_ctx = (void *) cipher_ctx;
    ctx->block = block;
    ctx->radix = radix;
    ctx->tweaklen = twklen;
    ctx->tweak = (unsigned char *) malloc(twklen);
    memcpy(ctx->tweak, tweak, twklen);
    return ctx;
cleanup:
    return NULL;
}

void WBCRYPTO_fpe_free(WBCRYPTO_fpe_context *ctx) {
    if (ctx) {
        if (ctx->tweak) {
            free(ctx->tweak);
        }
        free(ctx);
    }
}