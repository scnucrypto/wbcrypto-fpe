#ifndef WBCRYPTO_SM4_H
#define WBCRYPTO_SM4_H

# include <wbcrypto/conf.h>

# define SM4_KEY_SCHEDULE  32

#ifdef __cplusplus
extern "C" {
#endif

    struct sm4_context {
        uint32_t rk[SM4_KEY_SCHEDULE];
    };
    
    typedef struct sm4_context WBCRYPTO_sm4_context;

    /******************************************basic function**********************************************/
    /**
    * the function initializes the sm4 context
    * @param ctx Context to initialize, MUST be NULL
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_sm4_context *WBCRYPTO_sm4_context_init();

    /**
    * the function generate sm4 round key
    * @param key used to generate round key
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm4_init_key(WBCRYPTO_sm4_context *ctx, const uint8_t *key, size_t keylen);

    /**
    * the function is used to encrypt(**generally not used directly**)
    * @param ctx sm4-ctx must be init
    * @param input plaintext
    * @param output ciphertext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm4_encrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_sm4_context *ctx);

    /**
    * the function is used to decrypt(**generally not used directly**)
    * @param ctx sm4-ctx must be init
    * @param input ciphertext
    * @param output plaintext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm4_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_sm4_context *ctx);

    /**
     * free context
     * @param ctx
     */
    void WBCRYPTO_sm4_context_free(WBCRYPTO_sm4_context *ctx);
    
    /********************************************CBC mode************************************************/
    /**
    * sm4 encryption of cbc mode
    * @param in plaintext
    * @param inlen the length of input
    * @param out ciphertext
    * @param max_olen the longest storage space of ciphertext
    * @param use_olen the specific using space length of ciphertext
    * @param ctx sm4-ctx must be init
    * @param ivec initialization-vectors, the length must be 16
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm4_cbc_encrypt(const unsigned char *in, size_t inlen,
                                 unsigned char *out, size_t max_olen, size_t *use_olen,
                                 const WBCRYPTO_sm4_context *ctx,
                                 unsigned char ivec[16]);

    /**
    * sm4 decryption of cbc mode
    * @param in ciphertext
    * @param inlen the length of input
    * @param out plaintext
    * @param max_olen the longest storage space of plaintext
    * @param use_olen the specific using space length of plaintext
    * @param ctx sm4-ctx must be init
    * @param ivec initialization-vectors, the length must be 16
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm4_cbc_decrypt(const unsigned char *in, size_t inlen,
                                 unsigned char *out, size_t max_olen, size_t *use_olen,
                                 const WBCRYPTO_sm4_context *ctx,
                                 unsigned char ivec[16]);
    
    /********************************************GCM mode************************************************/
    /**
    * init the gcm128 context
    * @param key the context of sm4-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcm_context *WBCRYPTO_sm4_gcm_init(WBCRYPTO_sm4_context *key);
    
    /******************************************gcmfile mode*********************************************/
    /**
    * init the gcm-file context
    * @param key the context of sm4-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcmfile_context *WBCRYPTO_sm4_gcmfile_init(WBCRYPTO_sm4_context *key);

    /******************************************fpe-ff1 mode*********************************************/
    /**
    * Create a context instance for use with the FF1 algorithm
    * @param key the context of sm4-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_sm4_fpe_init(WBCRYPTO_sm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

    /******************************************aux-fun(unimportance)*********************************************/
    /**
    * auxiliary function, internal call
    * used to generate SM4 encryption and decryption round key
    */
    int aux_sm4_init_key(WBCRYPTO_sm4_context *ctx, const uint8_t *key, size_t keylen, int encmode);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_SM4_H
