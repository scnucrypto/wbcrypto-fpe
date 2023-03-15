#include <wbcrypto/aes.h>

WBCRYPTO_fpe_context *WBCRYPTO_aes_fpe_init(WBCRYPTO_aes_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_aes_encrypt);
    return ctx;
}