#include "local.h"

WBCRYPTO_co_wbsm4_enc_context *WBCRYPTO_co_wbsm4_enc_context_init() {
    int i, j, k;
    struct co_wbsm4_enc_context *ctx = malloc(sizeof(struct co_wbsm4_enc_context));
    if (ctx == NULL) {
        return NULL;
    }
    int rounds = 32;
    ctx->MM = (uint32_t ****) malloc(rounds * sizeof(uint32_t ***));
    ctx->CC = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));
    ctx->DD = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));
    ctx->Table = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));

    for (i = 0; i < rounds; i++) {
        ctx->MM[i] = (uint32_t ***) malloc((3) * sizeof(uint32_t **));
        ctx->CC[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        ctx->DD[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        ctx->Table[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
    }

    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 3; j++) {
            ctx->MM[i][j] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        }
    }
    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 3; j++) {
            for (k = 0; k < 4; k++) {
                ctx->MM[i][j][k] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            }
        }
    }

    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 4; j++) {
            ctx->CC[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            ctx->DD[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            ctx->Table[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
        }
    }
    return ctx;
}

void WBCRYPTO_co_wbsm4_enc_context_free(WBCRYPTO_co_wbsm4_enc_context *ctx) {
    memset(ctx, 0, sizeof(struct co_wbsm4_enc_context));
}

WBCRYPTO_co_wbsm4_dec_context *WBCRYPTO_co_wbsm4_dec_context_init() {
    int i, j, k;
    struct co_wbsm4_dec_context *ctx = malloc(sizeof(struct co_wbsm4_dec_context));
    if (ctx == NULL) {
        return NULL;
    }
    int rounds = 32;
    ctx->MM = (uint32_t ****) malloc(rounds * sizeof(uint32_t ***));
    ctx->CC = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));
    ctx->DD = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));
    ctx->Table = (uint32_t ***) malloc(rounds * sizeof(uint32_t **));

    for (i = 0; i < rounds; i++) {
        ctx->MM[i] = (uint32_t ***) malloc((3) * sizeof(uint32_t **));
        ctx->CC[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        ctx->DD[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        ctx->Table[i] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
    }

    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 3; j++) {
            ctx->MM[i][j] = (uint32_t **) malloc((4) * sizeof(uint32_t *));
        }
    }
    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 3; j++) {
            for (k = 0; k < 4; k++) {
                ctx->MM[i][j][k] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            }
        }
    }

    for (i = 0; i < rounds; i++) {
        for (j = 0; j < 4; j++) {
            ctx->CC[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            ctx->DD[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
            ctx->Table[i][j] = (uint32_t *) malloc((256) * sizeof(uint32_t));
        }
    }
    return ctx;
}

void WBCRYPTO_co_wbsm4_dec_context_free(WBCRYPTO_co_wbsm4_dec_context *ctx) {
    memset(ctx, 0, sizeof(struct co_wbsm4_dec_context));
}