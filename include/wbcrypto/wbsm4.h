#ifndef WBCRYPTO_WBSM4_H
#define WBCRYPTO_WBSM4_H

#include <wbcrypto/conf.h>
#include <WBMatrix/WBMatrix.h>
#include <wbcrypto/sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct wbsm4_context {
        int encmode;

        uint32_t MM[32][3][4][256];
        uint32_t CC[32][4][256];
        uint32_t DD[32][4][256];

        uint32_t SE[4][4][256];
        uint32_t FE[4][4][256];

        uint32_t Table[32][4][256];
    };

    typedef struct wbsm4_context WBCRYPTO_wbsm4_context;

    /******************************************basic function**********************************************/
    /**
    * the function initializes the wbsm4 context
    * @param encmode encrypto mode. {WBCRYPTO_ENCRYPT_MODE: encrypto mode; WBCRYPTO_DECRYPT_MODE: decrypto mode}
    * @param dummyrounds add extra dummyrounds, 1 dummyround will be expanded to 4 rounds in the runtime
    * @return ctx Context to initialize, NULL is fault, otherwise successful
    */
    WBCRYPTO_wbsm4_context *WBCRYPTO_wbsm4_context_init(int encmode);

    /**
    * free context
    * @param ctx
    */
    void WBCRYPTO_wbsm4_context_free(WBCRYPTO_wbsm4_context *ctx);

    /**
    * the function generate key-tables by the key in the context(the default dummyaround param is 1)
    * @param key key used to generate the key-tables, which need to hide
    * @param keylen key length
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_gen_table(WBCRYPTO_wbsm4_context *ctx, const uint8_t *key, size_t keylen);

    /**
    * the function is used to encrypt(**generally not used directly**)
    * @param ctx wbsm4-ctx must be init
    * @param input plaintext
    * @param output ciphertext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_encrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_wbsm4_context *ctx);

    /**
    * the function is used to decrypt(**generally not used directly**)
    * @param ctx wbsm4-ctx must be init
    * @param input ciphertext
    * @param output plaintext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_wbsm4_context *ctx);

    /******************************************key exchange aux-fun*********************************************/
    /**
    * convert T-box to file for storage
    * @param ctx the context with t-box which will convert T-box to file
    * @param fpath filepath for t-box storage
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_key2file(const WBCRYPTO_wbsm4_context *ctx, char *fpath);

    /**
    * generate T-box by reading keystore-file
    * @param ctx the context which is gen t-box by file, must bu NULL
    * @param fpath filepath for t-box storage
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_file2key(WBCRYPTO_wbsm4_context *ctx, char *fpath);

    /********************************************CBC mode************************************************/
    /**
    * wbsm4 encryption of cbc mode
    * @param in plaintext
    * @param inlen the length of input
    * @param out ciphertext
    * @param max_olen the longest storage space of ciphertext
    * @param use_olen the specific using space length of ciphertext
    * @param ctx wbsm4-ctx must be init
    * @param ivec initialization-vectors, the length must be 16
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_cbc_encrypt(const unsigned char *in, size_t inlen,
                                   unsigned char *out, size_t max_olen, size_t *use_olen,
                                   const WBCRYPTO_wbsm4_context *ctx,
                                   unsigned char ivec[16]);

    /**
    * wbsm4 decryption of cbc mode
    * @param in ciphertext
    * @param inlen the length of input
    * @param out plaintext
    * @param max_olen the longest storage space of plaintext
    * @param use_olen the specific using space length of plaintext
    * @param ctx wbsm4-ctx must be init
    * @param ivec initialization-vectors, the length must be 16
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbsm4_cbc_decrypt(const unsigned char *in, size_t inlen,
                                   unsigned char *out, size_t max_olen, size_t *use_olen,
                                   const WBCRYPTO_wbsm4_context *ctx,
                                   unsigned char ivec[16]);

    /********************************************GCM mode************************************************/
    /**
    * init the gcm128 context
    * @param key the context of wbsm4-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcm_context *WBCRYPTO_wbsm4_gcm_init(WBCRYPTO_wbsm4_context *key);

    /******************************************gcmfile mode*********************************************/
    /**
    * init the gcm-file context
    * @param key the context of wbsm4-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcmfile_context *WBCRYPTO_wbsm4_gcmfile_init(WBCRYPTO_wbsm4_context *key);

    /******************************************fpe mode*********************************************/
    /**
    * Create a context instance for use with the FF1 or FF3 algorithm
    * @param key the context of sm4-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_wbsm4_fpe_init(WBCRYPTO_wbsm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_WBSM4_H
