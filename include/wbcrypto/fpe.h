#ifndef WBCRYPTO_FPE_H
#define WBCRYPTO_FPE_H

#include <stdint.h>
#include <stddef.h>
#include <wbcrypto/conf.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct fpe_ctx {
        void *cipher_ctx; // cipher context used
        block128_f block; // encryption algorithm

        unsigned int radix;
        unsigned char *tweak;
        unsigned int tweaklen;
    };

    typedef struct fpe_ctx WBCRYPTO_fpe_context;

    /**
    * Create a context instance for use with the FF1 or FF3 algorithm
    *
    * The created instance can be used for encryption or decryption
    * or both. The instance is not thread-safe, though. For example,
    * multiple instances can be created and used in different, individual
    * threads. However, a single instance cannot be used for simultaneous
    * encryptions/decryptions in multiple threads.
    *
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_fpe_init(const uint8_t *tweak, size_t twklen, unsigned int radix,
                                            void *cipher_ctx, block128_f block);

    /**
    * Destroy the context structure associated with the FF1 or FF3 algorithm
    * @param ctx The pointer returned by the create function
    */
    void WBCRYPTO_fpe_free(WBCRYPTO_fpe_context *ctx);

    /**
    * Encrypt data using the FF1 algorithm
    *
    * Encryption is a "one-shot" operation. The entire plain text must
    * be passed in, and the entire cipher text is returned. The cipher
    * text uses the same "alphabet" as the plain text and will be the
    * same length as the plain text.
    *
    * @ctx: The pointer returned by the create function
    * @param input: A pointer to the location of the plain text. The plain text must
    *                be nul-terminated
    * @param output: A pointer to the location to output the cipher text. This space
    *                is allocated by the caller and must be at least as long as the
    *                plain text. The parameter must include space for a nul-terminator.
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_ff1_encrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output);

    /**
    * Decrypt data using the FF1 algorithm
    *
    * Decryption is a "one-shot" operation. The entire cipher text must
    * be passed in, and the entire plain text is returned.
    *
    * @param ctx: The pointer returned by the create function
    * @param input: A pointer to the location of the cipher text. The cipher text must
    *               be nul-terminated
    * @param output: A pointer to the location to output the plain text. This space
    *                is allocated by the caller and must be at least as long as the
    *                cipher text. The parameter must include space for a nul-terminator.
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_ff1_decrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output);

    /**
    * Encrypt data using the FF3 algorithm
    *
    * Encryption is a "one-shot" operation. The entire plain text must
    * be passed in, and the entire cipher text is returned. The cipher
    * text uses the same "alphabet" as the plain text and will be the
    * same length as the plain text.
    *
    * @ctx: The pointer returned by the create function
    * @param input: A pointer to the location of the plain text. The plain text must
    *                be nul-terminated
    * @param output: A pointer to the location to output the cipher text. This space
    *                is allocated by the caller and must be at least as long as the
    *                plain text. The parameter must include space for a nul-terminator.
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_ff3_encrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output);

    /**
    * Decrypt data using the FF3 algorithm
    *
    * Decryption is a "one-shot" operation. The entire cipher text must
    * be passed in, and the entire plain text is returned.
    *
    * @param ctx: The pointer returned by the create function
    * @param input: A pointer to the location of the cipher text. The cipher text must
    *               be nul-terminated
    * @param output: A pointer to the location to output the plain text. This space
    *                is allocated by the caller and must be at least as long as the
    *                cipher text. The parameter must include space for a nul-terminator.
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_ff3_decrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_FPE_H