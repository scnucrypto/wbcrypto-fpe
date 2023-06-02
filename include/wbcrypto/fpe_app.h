#ifndef WBCRYPTO_FPE_APP_H
#define WBCRYPTO_FPE_APP_H

#include <wbcrypto/fpe.h>
#include <wbcrypto/wbsm4.h>

#define WBCYRPTO_FPE_CIPHER_WBSM4 "wbsm4"

#define WBCYRPTO_FPE_FFX_FF1 "ff1"
#define WBCYRPTO_FPE_FFX_FF3 "ff3"

#ifdef __cplusplus
extern "C" {
#endif

    typedef int (*fpe_block128_f)(WBCRYPTO_fpe_context *key, const char *in, char *out);

    int WBCRYPTO_fpe_encrypt_phone(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone);

    int WBCRYPTO_fpe_decrypt_phone(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone);

    int WBCRYPTO_fpe_encrypt_phone_with_sample(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone, char *sample);

    int WBCRYPTO_fpe_decrypt_phone_with_sample(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone, char *sample);

    int WBCRYPTO_fpe_encrypt_idcard(WBCRYPTO_wbsm4_context *ctx, char *idcard, char *after_idcard);

    int WBCRYPTO_fpe_decrypt_idcard(WBCRYPTO_wbsm4_context *ctx, char *idcard, char *after_idcard);

    int WBCRYPTO_fpe_encrypt_idcard_with_sample(WBCRYPTO_wbsm4_context *ctx, char *idcard, char *after_idcard, char *sample);

    int WBCRYPTO_fpe_decrypt_idcard_with_sample(WBCRYPTO_wbsm4_context *ctx, char *idcard, char *after_idcard, char *sample);

    int WBCRYPTO_fpe_encrypt_cn_utf8(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn);

    int WBCRYPTO_fpe_decrypt_cn_utf8(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn);

    int WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn, char *sample);

    int WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn, char *sample);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_FPE_APP_H