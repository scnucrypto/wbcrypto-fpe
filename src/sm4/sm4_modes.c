#include <wbcrypto/sm4.h>

int WBCRYPTO_sm4_cbc_encrypt(const unsigned char *in, size_t inlen,
                              unsigned char *out, size_t max_olen, size_t *use_olen,
                              const WBCRYPTO_sm4_context *ctx,
                              unsigned char ivec[16]){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_cbc128_encrypt(in, inlen, out, max_olen, use_olen, ctx, ivec,
                                    (block128_f) WBCRYPTO_sm4_encrypt)
    );
    ret=1;
cleanup:
    return ret;
}

int WBCRYPTO_sm4_cbc_decrypt(const unsigned char *in, size_t inlen,
                              unsigned char *out, size_t max_olen, size_t *use_olen,
                              const WBCRYPTO_sm4_context *ctx,
                              unsigned char ivec[16]){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_cbc128_decrypt(in, inlen, out, max_olen, use_olen, ctx, ivec,
                                    (block128_f) WBCRYPTO_sm4_decrypt)
    );
    *use_olen = WBCRYPTO_padding_pkcs7_separate_length(out, inlen);
    ret=1;
cleanup:
    return ret;
}

WBCRYPTO_gcm_context *WBCRYPTO_sm4_gcm_init(WBCRYPTO_sm4_context *key){
    WBCRYPTO_gcm_context *ctx=WBCRYPTO_gcm_init(key, (block128_f) WBCRYPTO_sm4_encrypt);
    return ctx;
}

WBCRYPTO_gcmfile_context *WBCRYPTO_sm4_gcmfile_init(WBCRYPTO_sm4_context *key){
    WBCRYPTO_gcmfile_context *ctx=WBCRYPTO_gcmfile_init(key,(block128_f) WBCRYPTO_sm4_encrypt);
    return ctx;
}
