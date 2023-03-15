#include <wbcrypto/fpe.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/bn.h>
#include "fpe_locl.h"

// convert numeral string to number
void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx),
            *x = BN_CTX_get(ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = 0; i < len; ++i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(ctx);
}

// convert number to numeral string
void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *dv = BN_CTX_get(ctx),
            *rem = BN_CTX_get(ctx),
            *r = BN_CTX_get(ctx),
            *XX = BN_CTX_get(ctx);

    BN_copy(XX, X);
    BN_set_word(r, radix);
    memset(Y, 0, len << 2);

    for (int i = len - 1; i >= 0; --i) {
        // XX / r = dv ... rem
        BN_div(dv, rem, XX, r, ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(rem);
        // XX = XX / r
        BN_copy(XX, dv);
    }

    BN_CTX_end(ctx);
}

int WBCRYPTO_ff1_encrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = {1};

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);

    unsigned int temp = (unsigned int) ceil(v * log2(ctx->radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ((-ctx->tweaklen - b - 1) % 16 + 16) % 16;
    int Qlen = ctx->tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *) malloc(Qlen), *Bytes = (unsigned char *) malloc(b);

    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (ctx->radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (ctx->tweaklen >> 24) & 0xff;
        P[13] = (ctx->tweaklen >> 16) & 0xff;
        P[14] = (ctx->tweaklen >> 8) & 0xff;
        P[15] = ctx->tweaklen & 0xff;
    } else {
        *((unsigned int *) (P + 3)) = (ctx->radix << 8) | 10;
        *((unsigned int *) (P + 8)) = inlen;
        *((unsigned int *) (P + 12)) = ctx->tweaklen;
    }

    // initialize Q
    memcpy(Q, ctx->tweak, ctx->tweaklen);
    memset(Q + ctx->tweaklen, 0x00, pad);
    assert(ctx->tweaklen + pad - 1 <= Qlen);

    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *) malloc(Slen);
    for (int i = 0; i < FF1_ROUNDS; ++i) {
        // v
        int m = (i & 1) ? v : u;

        // i
        Q[ctx->tweaklen + pad] = i & 0xff;
        str2num(bnum, B, ctx->radix, inlen - m, bn_ctx);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        memset(Q + Qlen - b, 0x00, b);

        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q), P is always 16 bytes long
        // AES_encrypt(P, R, &aes_enc_ctx);
        (*ctx->block)(P, R, ctx->cipher_ctx);
        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;
        for (int cc = 0; cc < count; ++cc) {
            for (int j = 0; j < 16; ++j) Ri[j] = Qi[j] ^ R[j];
            // AES_encrypt(Ri, R, &aes_enc_ctx);
            (*ctx->block)(Ri, R, ctx->cipher_ctx);
            Qi += 16;
        }

        // iii 
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        assert(Slen >= 16);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *((unsigned int *) tmp + 3) = j;

            for (int k = 0; k < 16; ++k) tmp[k] ^= R[k];
            // AES_encrypt(tmp, SS, &aes_enc_ctx);
            (*ctx->block)(tmp, SS, ctx->cipher_ctx);
            assert((S + 16 * j)[0] == 0x00);
            assert(16 + 16 * j <= Slen);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(A, radix, m) + y) % qpow(radix, m);
        str2num(anum, A, ctx->radix, m, bn_ctx);
        // anum = (anum + y) mod qpow_uv
        if (m == u) BN_mod_add(c, anum, y, qpow_u, bn_ctx);
        else BN_mod_add(c, anum, y, qpow_v, bn_ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        num2str(c, B, ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);

    ret = 1;
cleanup:
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    free(Bytes);
    free(Q);
    free(S);
    return ret;
}

int WBCRYPTO_ff1_decrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = {1};

    // AES_KEY aes_enc_ctx;
    // const uint8_t userKey[] = {
    //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    // };
    // AES_set_encrypt_key(userKey, 128, &aes_enc_ctx);

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);

    unsigned int temp = (unsigned int) ceil(v * log2(ctx->radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ((-ctx->tweaklen - b - 1) % 16 + 16) % 16;
    int Qlen = ctx->tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *) malloc(Qlen), *Bytes = (unsigned char *) malloc(b);
    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (ctx->radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (ctx->tweaklen >> 24) & 0xff;
        P[13] = (ctx->tweaklen >> 16) & 0xff;
        P[14] = (ctx->tweaklen >> 8) & 0xff;
        P[15] = ctx->tweaklen & 0xff;
    } else {
        *((unsigned int *) (P + 3)) = (ctx->radix << 8) | 10;
        *((unsigned int *) (P + 8)) = inlen;
        *((unsigned int *) (P + 12)) = ctx->tweaklen;
    }

    // initialize Q
    memcpy(Q, ctx->tweak, ctx->tweaklen);
    memset(Q + ctx->tweaklen, 0x00, pad);
    assert(ctx->tweaklen + pad - 1 <= Qlen);

    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *) malloc(Slen);
    for (int i = FF1_ROUNDS - 1; i >= 0; --i) {
        // v
        int m = (i & 1) ? v : u;

        // i
        Q[ctx->tweaklen + pad] = i & 0xff;
        str2num(anum, A, ctx->radix, inlen - m, bn_ctx);
        memset(Q + Qlen - b, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q)
        memset(R, 0x00, sizeof(R));
        // AES_encrypt(P, R, &aes_enc_ctx);
        (*ctx->block)(P, R, ctx->cipher_ctx);
        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;
        for (int cc = 0; cc < count; ++cc) {
            for (int j = 0; j < 16; ++j) Ri[j] = Qi[j] ^ R[j];
            // AES_encrypt(Ri, R, &aes_enc_ctx);
            (*ctx->block)(Ri, R, ctx->cipher_ctx);
            Qi += 16;
        }

        // iii 
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *((unsigned int *) tmp + 3) = j;

            for (int k = 0; k < 16; ++k) tmp[k] ^= R[k];
            // AES_encrypt(tmp, SS, &aes_enc_ctx);
            (*ctx->block)(tmp, SS, ctx->cipher_ctx);
            assert((S + 16 * j)[0] == 0x00);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(B, radix, m) - y) % qpow(radix, m);
        str2num(bnum, B, ctx->radix, m, bn_ctx);
        if (m == u) BN_mod_sub(c, bnum, y, qpow_u, bn_ctx);
        else BN_mod_sub(c, bnum, y, qpow_v, bn_ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        num2str(c, A, ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);

    ret = 1;
cleanup:
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(y);
    BN_clear_free(c);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    free(Bytes);
    free(Q);
    free(S);
    return ret;
}
