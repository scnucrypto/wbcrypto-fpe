#ifndef WBCRYPTO_FPE_APP_H
#define WBCRYPTO_FPE_APP_H

#include <wbcrypto/fpe.h>

#define WBCYRPTO_FPE_CIPHER_AES "aes"
#define WBCYRPTO_FPE_CIPHER_SM4 "sm4"
#define WBCYRPTO_FPE_CIPHER_WBSM4 "wbsm4"

#define WBCYRPTO_FPE_FFX_FF1 "ff1"
#define WBCYRPTO_FPE_FFX_FF3 "ff3"

#ifdef __cplusplus
extern "C" {
#endif

    typedef int (*fpe_block128_f)(WBCRYPTO_fpe_context *key, const char *in, char *out);

    struct fpe_app_ctx {
        void *cipher_ctx;
        char *cipher;
        char *ffx;
    };

    typedef struct fpe_app_ctx WBCRYPTO_fpe_app_context;

    int WBCRYPTO_fpe_app_init(WBCRYPTO_fpe_app_context *ctx, const uint8_t *key, size_t keylen, char *cipher, char *ffx);

    int WBCRYPTO_fpe_encrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone);

    int WBCRYPTO_fpe_decrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone);

    int WBCRYPTO_fpe_encrypt_phone_with_sample(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone, char *sample);

    int WBCRYPTO_fpe_decrypt_phone_with_sample(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone, char *sample);

    int WBCRYPTO_fpe_encrypt_idcard(WBCRYPTO_fpe_app_context *ctx, char *idcard, char *after_idcard);

    int WBCRYPTO_fpe_decrypt_idcard(WBCRYPTO_fpe_app_context *ctx, char *idcard, char *after_idcard);

    int WBCRYPTO_fpe_encrypt_idcard_with_sample(WBCRYPTO_fpe_app_context *ctx, char *idcard, char *after_idcard, char *sample);

    int WBCRYPTO_fpe_decrypt_idcard_with_sample(WBCRYPTO_fpe_app_context *ctx, char *idcard, char *after_idcard, char *sample);

    int WBCRYPTO_fpe_encrypt_cn_utf8(WBCRYPTO_fpe_app_context *ctx, char *cn, char *after_cn);

    int WBCRYPTO_fpe_decrypt_cn_utf8(WBCRYPTO_fpe_app_context *ctx, char *cn, char *after_cn);

    int WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(WBCRYPTO_fpe_app_context *ctx, char *cn, char *after_cn, char *sample);

    int WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(WBCRYPTO_fpe_app_context *ctx, char *cn, char *after_cn, char *sample);

    int WBCRYPTO_fpe_encrypt_name(WBCRYPTO_fpe_app_context *ctx, char *name, char *after_name);

    int WBCRYPTO_fpe_decrypt_name(WBCRYPTO_fpe_app_context *ctx, char *name, char *after_name);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_FPE_APP_H