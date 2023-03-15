#ifndef WBCRYPTO_MODES_H
#define WBCRYPTO_MODES_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wbcrypto/error.h>
#include <wbcrypto/utils.h>


#ifdef  __cplusplus
extern "C" {
#endif

#ifdef IMPORT_OPENSSL
    #include <openssl/modes.h>
#else
    typedef int (*block128_f) (const unsigned char in[16], unsigned char out[16],
                               const void *key);

    struct gcm128_context{
        uint64_t len;                   // cipher data length processed so far
        uint64_t add_len;               // total add data length
        uint64_t HL[16];                // precalculated lo-half HTable
        uint64_t HH[16];                // precalculated hi-half HTable
        unsigned char base_ectr[16];    // first counter-mode cipher output for tag
        unsigned char y[16];            // the current cipher-input IV|Counter value
        unsigned char buf[16];          // buf working value
        void *key;                      // cipher context used
        block128_f block;               // encryption algorithm
    };
#endif
    /******************************************************************
    * CBC mode
    *****************************************************************/
    /**
     * cbc-mode encryption
     * @param in plaintext
     * @param inlen size of plaintext
     * @param out ciphertext
     * @param max_olen the longest storage space of ciphertext
     * @param use_olen the specific using space length of ciphertext
     * @param key A context of CBC mode
     * @param ivec initialization-vectors
     * @param block A context of basic encryption function
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_cbc128_encrypt(const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t max_olen, size_t *use_olen,
                                const void *key, unsigned char ivec[16],
                                block128_f block);
    /**
     * cbc-mode decryption
     * @param in ciphertext
     * @param inlen size of ciphertext
     * @param max_olen the longest storage space of plaintext
     * @param use_olen the specific using space length of plaintext
     * @param outlen size of plaintext
     * @param key A context of CBC mode
     * @param ivec initialization-vectors
     * @param block A context of basic decryption function
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_cbc128_decrypt(const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t max_olen, size_t *use_olen,
                                const void *key, unsigned char ivec[16],
                                block128_f block);

    /******************************************************************
    * GCM mode
    *****************************************************************/
    /**
     * gcm-mode context
     * If need to use GCM mode, the user must initialize context
     */
    typedef struct gcm128_context WBCRYPTO_gcm_context;

    /**
     * init the gcm128 context
     * @param key the context of some-algorithm
     * @param block the enc/dec-function of some-algorithm, often use encryption function
     * @return NULL is fault, otherwise successful
     */
    WBCRYPTO_gcm_context *WBCRYPTO_gcm_init(void *key, block128_f block);

    /**
     * set initialization-vec
     * @param ctx the context of gcm-mode
     * @param iv initialization-vector
     * @param len the length of initialization-vec
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_setiv(WBCRYPTO_gcm_context *ctx,
                          const unsigned char *iv, size_t len);

    /**
     * set additional-info
     * @param ctx the context of gcm-mode
     * @param aad additional information
     * @param len the length of additional-info
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_aad(WBCRYPTO_gcm_context *ctx,
                          const unsigned char *aad, size_t len);

    /**
     * encryption of gcm mode
     * @param ctx the context of gcm-mode
     * @param in plaintext
     * @param inlen size of plaintext
     * @param out ciphertext
     * @param outlen size of ciphertext
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_encrypt(WBCRYPTO_gcm_context *ctx,
                            const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t outlen);

    /**
    * decryption of gcm mode
    * @param ctx the context of gcm-mode
    * @param in ciphertext
    * @param inlen size of ciphertext
    * @param out plaintext
    * @param outlen size of plaintext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcm_decrypt(WBCRYPTO_gcm_context *ctx,
                            const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t outlen);

    /**
    * obtain the tag(MAC value)
    * @param ctx the context of gcm-mode
    * @param tag input tag
    * @param len the length of tag
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcm_finish(WBCRYPTO_gcm_context *ctx,
                               unsigned char *tag, size_t len);

    /**
     * release the context of gcm-mode
     * @param ctx
     */
    void WBCRYPTO_gcm_free(WBCRYPTO_gcm_context *ctx);

    /******************************************************************
    * Encrypt/Decrypt files in GCM mode
    ******************************************************************/
    #define WBCRYPTO_GCM_FILE_TAG_LEN 16
    #define WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN 128

    struct gcmfile_context{
        WBCRYPTO_gcm_context *gcm;
        unsigned char tag[WBCRYPTO_GCM_FILE_TAG_LEN];
    };

    /**
    * gcmfile-mode context
    * If need to use gcmfile mode, the user must initialize context
    */
    typedef struct gcmfile_context WBCRYPTO_gcmfile_context;

    /**
     * init the gcm-file context
     * @param key the context of some-algorithm
     * @param block the enc/dec-function of some-algorithm, often use enc-func
     * @return NULL is fault, otherwise successful
     */
    WBCRYPTO_gcmfile_context *WBCRYPTO_gcmfile_init(void *key, block128_f block);

    /**
    * set initialization-vec
    * @param ctx the context of gcmfile-mode
    * @param iv initialization-vector
    * @param len the length of initialization-vec
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcmfile_setiv(WBCRYPTO_gcmfile_context *ctx,
                               const unsigned char *iv, size_t len);

    /**
    * set additional-info
    * @param ctx the context of gcmfile-mode
    * @param aad additional information
    * @param len the length of additional-info
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcmfile_aad(WBCRYPTO_gcmfile_context *ctx,
                               const unsigned char *aad, size_t len);

    /**
    * encryption of gcm-file mode
    * @param ctx the context of gcm-mode
    * @param infpath the path of file which need to encrypt
    * @param outfpath output file path
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcmfile_encrypt(WBCRYPTO_gcmfile_context *ctx,
                                 char *infpath, char *outfpath);

    /**
    * decryption of gcm-file mode
    * @param ctx the context of gcm-mode
    * @param infpath the path of file which need to decrypt
    * @param outfpath output file path
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcmfile_decrypt(WBCRYPTO_gcmfile_context *ctx,
                                 char *infpath, char *outfpath);

    /**
    * release the context of gcm-file-mode
    * @param ctx the context of gcm-mode
    */
    void WBCRYPTO_gcmfile_free(WBCRYPTO_gcmfile_context *ctx);

#ifdef  __cplusplus
}
#endif

#endif //WBCRYPTO_MODES_H