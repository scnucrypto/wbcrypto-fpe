#ifndef WBCRYPTO_SE_WBSM4_H
#define WBCRYPTO_SE_WBSM4_H

#include <wbcrypto/conf.h>
#include <WBMatrix/WBMatrix.h>
#include <wbcrypto/sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct se_wbsm4_context {
        int encmode;
        Aff32 M[32][3];
        Aff32 C[32];
        Aff32 D[32];
        Aff32 SE[4];
        Aff32 FE[4];
    };

    typedef struct se_wbsm4_context WBCRYPTO_se_wbsm4_context;

    /******************************************basic function**********************************************/
    /**
    * the function initializes the se_wbsm4 context
    * @param encmode encrypto mode. {WBCRYPTO_ENCRYPT_MODE: encrypto mode; WBCRYPTO_DECRYPT_MODE: decrypto mode}
    * @param dummyrounds add extra dummyrounds, 1 dummyround will be expanded to 4 rounds in the runtime
    * @return ctx Context to initialize, NULL is fault, otherwise successful
    */
    WBCRYPTO_se_wbsm4_context *WBCRYPTO_se_wbsm4_context_init(int encmode);

    /**
    * free se_wbsm4 context
    * @param ctx
    */
    void WBCRYPTO_se_wbsm4_context_free(WBCRYPTO_se_wbsm4_context *ctx);

    /**
    * the function generate key-tables by the key in the context
    * @param key key used to generate the key-tables, which need to hide
    * @param keylen key length
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_se_wbsm4_gen_table(WBCRYPTO_se_wbsm4_context *ctx, const uint8_t *key, size_t keylen);

    /**
    * the function is used to encrypt(**generally not used directly**)
    * @param ctx se-wbsm4-ctx must be init
    * @param input plaintext
    * @param output ciphertext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_se_wbsm4_encrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_se_wbsm4_context *ctx);

    /**
    * the function is used to decrypt(**generally not used directly**)
    * @param ctx se-wbsm4-ctx must be init
    * @param input ciphertext
    * @param output plaintext
    * @return 1 if success, 0 if error
    */
//    int WBCRYPTO_se_wbsm4_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_se_wbsm4_context *ctx);

    /******************************************fpe mode*********************************************/
    /**
    * Create a context instance for use with the FF1 or FF3 algorithm
    * @param key the context of sm4-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_se_wbsm4_fpe_init(WBCRYPTO_se_wbsm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix);
#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_SE_WBSM4_H
