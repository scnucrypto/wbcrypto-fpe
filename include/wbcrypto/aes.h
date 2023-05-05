#ifndef WBCRYPTO_AES_H
#define WBCRYPTO_AES_H

# include <wbcrypto/conf.h>
# include <openssl/aes.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct aes_context {
        AES_KEY aes_key;
    };

    typedef struct aes_context WBCRYPTO_aes_context;

    /******************************************basic function**********************************************/
    /**
    * the function initializes the aes context
    * @param ctx Context to initialize, MUST be NULL
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_aes_context *WBCRYPTO_aes_context_init();

    /**
    * the function init aes context
    * @param key used to generate round key
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_aes_init_key(WBCRYPTO_aes_context *ctx, const uint8_t *key, size_t keylen);

    /**
    * the function is used to encrypt(**generally not used directly**)
    * @param ctx aes-ctx must be init
    * @param input plaintext
    * @param output ciphertext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_aes_encrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_aes_context *ctx);

    /**
    * the function is used to decrypt(**generally not used directly**)
    * @param ctx aes-ctx must be init
    * @param input ciphertext
    * @param output plaintext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_aes_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_aes_context *ctx);

    /**
    * free context
    * @param ctx
    */
    void WBCRYPTO_aes_context_free(WBCRYPTO_aes_context *ctx);

    /******************************************fpe mode*********************************************/
    /**
    * Create a context instance for use with the FF1 algorithm
    * @param key the context of aes-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_aes_fpe_init(WBCRYPTO_aes_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_AES_H
