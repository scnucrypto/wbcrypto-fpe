#ifndef WBCRYPTO_SM3_H
#define WBCRYPTO_SM3_H

# include <wbcrypto/conf.h>

# define SM3_WORD unsigned int

# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

#ifdef __cplusplus
extern "C" {
#endif

    struct sm3_context {
        unsigned int A, B, C, D, E, F, G, H;
        unsigned int Nl, Nh;
        unsigned int data[SM3_LBLOCK];
        unsigned int num;
    };

    typedef struct sm3_context WBCRYPTO_sm3_context;

    /**
     * initialize sm3 context
     * @param ctx sm3-context
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_sm3_init(WBCRYPTO_sm3_context *ctx);

    /**
     * the intermediate process of sm3 calculation
     * @param ctx sm3-context, must be init
     * @param msg message to hash
     * @param msglen message length
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_sm3_update(WBCRYPTO_sm3_context *ctx, const void *msg, size_t msglen);

    /**
     * get the digest of sm3-alg
     * @param ctx sm3-context, must be updated
     * @param digest the digest
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_sm3_final(WBCRYPTO_sm3_context *ctx, unsigned char *digest);

    /**
    * SM3 calculation
    * @param msg message to hash
    * @param msglen message length
    * @param digest the digest
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_sm3(const unsigned char *msg, size_t msglen, unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_SM3_H
