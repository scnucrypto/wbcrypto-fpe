#include "local.h"

WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_enc_fpe_init(WBCRYPTO_co_wbsm4_enc_context *key, const char *twkbuf, size_t twklen, unsigned int radix){
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_co_wbsm4_encrypt);
    return ctx;
}

WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_dec_fpe_init(WBCRYPTO_co_wbsm4_dec_context *key, const char *twkbuf, size_t twklen, unsigned int radix){
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_co_wbsm4_decrypt);
    return ctx;
}

WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_dec_ee_fpe_init(WBCRYPTO_co_wbsm4_dec_ee_context *key, const char *twkbuf, size_t twklen, unsigned int radix){
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_co_wbsm4_ee_decrypt);
    return ctx;
}