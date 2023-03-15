#include <wbcrypto/fpe.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/bn.h>
#include "fpe_locl.h"

void rev_bytes(unsigned char X[], int len) {
    int hlen = len >> 1;
    for (int i = 0; i < hlen; ++i) {
        unsigned char tmp = X[i];
        X[i] = X[len - i - 1];
        X[len - i - 1] = tmp;
    }
    return;
}

// convert numeral string in reverse order to number
void str2num_rev(BIGNUM *Y, const unsigned int *X, unsigned int radix, unsigned int len, BN_CTX *bn_ctx) {
    BN_CTX_start(bn_ctx);
    BIGNUM *r = BN_CTX_get(bn_ctx),
            *x = BN_CTX_get(bn_ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = len - 1; i >= 0; --i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, bn_ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(bn_ctx);
}

// convert number to numeral string in reverse order
void num2str_rev(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *bn_ctx) {
    BN_CTX_start(bn_ctx);
    BIGNUM *dv = BN_CTX_get(bn_ctx),
            *rem = BN_CTX_get(bn_ctx),
            *r = BN_CTX_get(bn_ctx),
            *XX = BN_CTX_get(bn_ctx);

    BN_copy(XX, X);
    BN_set_word(r, radix);
    memset(Y, 0, len << 2);

    for (int i = 0; i < len; ++i) {
        // XX / r = dv ... rem
        BN_div(dv, rem, XX, r, bn_ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(rem);
        // XX = XX / r
        BN_copy(XX, dv);
    }

    BN_CTX_end(bn_ctx);
}

int WBCRYPTO_ff3_encrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);

    for (int i = 0; i < FF3_ROUNDS; ++i) {
        // i
        unsigned int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        str2num_rev(bnum, B, ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->block)(P, S, ctx->cipher_ctx);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(anum, A, ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_add(c, anum, y, qpow_v, bn_ctx);
        else BN_mod_add(c, anum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, B, ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);

    ret = 1;
cleanup:
    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(Bytes);
    return ret;
}

int WBCRYPTO_ff3_decrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

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
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);
    for (int i = FF3_ROUNDS - 1; i >= 0; --i) {
        // i
        int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // ii

        str2num_rev(anum, A, ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        memset(S, 0x00, sizeof(S));
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->block)(P, S, ctx->cipher_ctx);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(bnum, B, ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_sub(c, bnum, y, qpow_v, bn_ctx);
        else BN_mod_sub(c, bnum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, A, ctx->radix, m, bn_ctx);
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
    OPENSSL_free(Bytes);
    return ret;
}