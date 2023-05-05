#include "se_wbsm4_local.h"

WBCRYPTO_fpe_context *WBCRYPTO_se_wbsm4_fpe_init(WBCRYPTO_se_wbsm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_se_wbsm4_encrypt);
    return ctx;
}