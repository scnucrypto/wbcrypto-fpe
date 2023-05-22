#include "wbsm4_local.h"

WBCRYPTO_wbsm4_context *WBCRYPTO_wbsm4_context_init(int encmode){
    struct wbsm4_context *ctx=malloc(sizeof(struct wbsm4_context));
    if(ctx==NULL){
        return NULL;
    }
    ctx->encmode=encmode;
    return ctx;
}

void WBCRYPTO_wbsm4_context_free(WBCRYPTO_wbsm4_context *ctx){
    memset(ctx,0,sizeof(struct wbsm4_context));
}

int WBCRYPTO_wbsm4_encrypt(const unsigned char *in, unsigned char *out, WBCRYPTO_wbsm4_context *ctx){
    int ret=0;
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(in);
    x1 = GET32(in + 4);
    x2 = GET32(in + 8);
    x3 = GET32(in + 12);

    x0 = ctx->SE[0][0][(x0 >> 24) & 0xff] ^ ctx->SE[0][1][(x0 >> 16) & 0xff] ^ ctx->SE[0][2][(x0 >> 8) & 0xff] ^ ctx->SE[0][3][x0 & 0xff];
    x1 = ctx->SE[1][0][(x1 >> 24) & 0xff] ^ ctx->SE[1][1][(x1 >> 16) & 0xff] ^ ctx->SE[1][2][(x1 >> 8) & 0xff] ^ ctx->SE[1][3][x1 & 0xff];
    x2 = ctx->SE[2][0][(x2 >> 24) & 0xff] ^ ctx->SE[2][1][(x2 >> 16) & 0xff] ^ ctx->SE[2][2][(x2 >> 8) & 0xff] ^ ctx->SE[2][3][x2 & 0xff];
    x3 = ctx->SE[3][0][(x3 >> 24) & 0xff] ^ ctx->SE[3][1][(x3 >> 16) & 0xff] ^ ctx->SE[3][2][(x3 >> 8) & 0xff] ^ ctx->SE[3][3][x3 & 0xff];

    for(i = 0; i < 32; i++)
    {
        xt1 = ctx->MM[i][0][0][(x1 >> 24) & 0xff] ^ ctx->MM[i][0][1][(x1 >> 16) & 0xff] ^ ctx->MM[i][0][2][(x1 >> 8) & 0xff] ^ ctx->MM[i][0][3][x1 & 0xff];
        xt2 = ctx->MM[i][1][0][(x2 >> 24) & 0xff] ^ ctx->MM[i][1][1][(x2 >> 16) & 0xff] ^ ctx->MM[i][1][2][(x2 >> 8) & 0xff] ^ ctx->MM[i][1][3][x2 & 0xff];
        xt3 = ctx->MM[i][2][0][(x3 >> 24) & 0xff] ^ ctx->MM[i][2][1][(x3 >> 16) & 0xff] ^ ctx->MM[i][2][2][(x3 >> 8) & 0xff] ^ ctx->MM[i][2][3][x3 & 0xff];
        x4 = xt1 ^ xt2 ^ xt3;
        x4 = ctx->Table[i][0][(x4 >> 24) & 0xff] ^ ctx->Table[i][1][(x4 >> 16) & 0xff] ^ ctx->Table[i][2][(x4 >> 8) & 0xff] ^ ctx->Table[i][3][x4 & 0xff];
        xt0 = ctx->CC[i][0][(x0 >> 24) & 0xff] ^ ctx->CC[i][1][(x0 >> 16) & 0xff] ^ ctx->CC[i][2][(x0 >> 8) & 0xff] ^ ctx->CC[i][3][x0 & 0xff];
        xt4 = ctx->DD[i][0][(x4 >> 24) & 0xff] ^ ctx->DD[i][1][(x4 >> 16) & 0xff] ^ ctx->DD[i][2][(x4 >> 8) & 0xff] ^ ctx->DD[i][3][x4 & 0xff];
        x4 = xt0 ^ xt4;

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    x3 = ctx->FE[0][0][(x3 >> 24) & 0xff] ^ ctx->FE[0][1][(x3 >> 16) & 0xff] ^ ctx->FE[0][2][(x3 >> 8) & 0xff] ^ ctx->FE[0][3][x3 & 0xff];
    x2 = ctx->FE[1][0][(x2 >> 24) & 0xff] ^ ctx->FE[1][1][(x2 >> 16) & 0xff] ^ ctx->FE[1][2][(x2 >> 8) & 0xff] ^ ctx->FE[1][3][x2 & 0xff];
    x1 = ctx->FE[2][0][(x1 >> 24) & 0xff] ^ ctx->FE[2][1][(x1 >> 16) & 0xff] ^ ctx->FE[2][2][(x1 >> 8) & 0xff] ^ ctx->FE[2][3][x1 & 0xff];
    x0 = ctx->FE[3][0][(x0 >> 24) & 0xff] ^ ctx->FE[3][1][(x0 >> 16) & 0xff] ^ ctx->FE[3][2][(x0 >> 8) & 0xff] ^ ctx->FE[3][3][x0 & 0xff];

    PUT32(x3, out);
    PUT32(x2, out + 4);
    PUT32(x1, out + 8);
    PUT32(x0, out + 12);
	ret=1;
cleanup:
    return ret;
}

int WBCRYPTO_wbsm4_decrypt(const unsigned char *in, unsigned char *out, WBCRYPTO_wbsm4_context *ctx){
    return WBCRYPTO_wbsm4_encrypt(in, out, ctx);
}