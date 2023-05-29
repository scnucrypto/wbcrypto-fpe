#ifndef WBCRYPTO_CO_WBSM4_H
#define WBCRYPTO_CO_WBSM4_H

#include <wbcrypto/conf.h>
#include <WBMatrix/WBMatrix.h>
#include <wbcrypto/sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

    /******************************************encrypt**********************************************/
    struct co_wbsm4_enc_context {
        uint32_t ****MM;        //MM[32]][3][4][256]
        uint32_t ***CC;         //CC[32][4][256]
        uint32_t ***DD;         //DD[32][4][256]
        uint32_t SE[4][4][256];
        uint32_t ***Table;      //Table[32][4][256]
    };
    typedef struct co_wbsm4_enc_context WBCRYPTO_co_wbsm4_enc_context;
    // init
    WBCRYPTO_co_wbsm4_enc_context *WBCRYPTO_co_wbsm4_enc_context_init();
    void WBCRYPTO_co_wbsm4_enc_context_free(WBCRYPTO_co_wbsm4_enc_context *ctx);

    /******************************************decrypt**********************************************/
    struct co_wbsm4_dec_context {
        uint32_t ****MM;        //MM[32]][3][4][256]
        uint32_t ***CC;         //CC[32][4][256]
        uint32_t ***DD;         //DD[32][4][256]
        uint32_t ***Table;      //Table[32][4][256]
    };
    typedef struct co_wbsm4_dec_context WBCRYPTO_co_wbsm4_dec_context;

    struct co_wbsm4_dec_ee_context {
        uint32_t FE[4][4][256];
    };
    typedef struct co_wbsm4_dec_ee_context WBCRYPTO_co_wbsm4_dec_ee_context;
    // init
    WBCRYPTO_co_wbsm4_dec_context *WBCRYPTO_co_wbsm4_dec_context_init();
    void WBCRYPTO_co_wbsm4_dec_context_free(WBCRYPTO_co_wbsm4_dec_context *ctx);

    /******************************************basic function**********************************************/
    int WBCRYPTO_co_wbsm4_gen_table1(WBCRYPTO_co_wbsm4_enc_context *enc_ctx, WBCRYPTO_co_wbsm4_dec_context *dec_ctx, const uint8_t *key, size_t keylen);
    int WBCRYPTO_co_wbsm4_gen_table2(WBCRYPTO_co_wbsm4_dec_context *dec_ctx, WBCRYPTO_co_wbsm4_dec_ee_context *ee_ctx);

    int WBCRYPTO_co_wbsm4_encrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_co_wbsm4_enc_context *ctx);

    int WBCRYPTO_co_wbsm4_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_co_wbsm4_dec_context *ctx);

    int WBCRYPTO_co_wbsm4_ee_decrypt(const unsigned char *input, unsigned char *output, WBCRYPTO_co_wbsm4_dec_ee_context *ctx);

    /******************************************key exchange*********************************************/
    int WBCRYPTO_co_wbsm4_enc_key2file(const WBCRYPTO_co_wbsm4_enc_context *ctx, char *fpath);
    int WBCRYPTO_co_wbsm4_enc_file2key(WBCRYPTO_co_wbsm4_enc_context *ctx, char *fpath);

    int WBCRYPTO_co_wbsm4_dec_key2file(const WBCRYPTO_co_wbsm4_dec_context *ctx, char *fpath);
    int WBCRYPTO_co_wbsm4_decc_file2key(WBCRYPTO_co_wbsm4_dec_context *ctx, char *fpath);

    int WBCRYPTO_co_wbsm4_dec_ee_key2file(const WBCRYPTO_co_wbsm4_dec_ee_context *ctx, char *fpath);
    int WBCRYPTO_co_wbsm4_dec_ee_file2key(WBCRYPTO_co_wbsm4_dec_ee_context *ctx, char *fpath);

    /******************************************fpe mode*********************************************/
//    WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_enc_fpe_init(WBCRYPTO_co_wbsm4_enc_context *key, const char *twkbuf, size_t twklen, unsigned int radix);
//    WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_dec_fpe_init(WBCRYPTO_co_wbsm4_dec_context *key, const char *twkbuf, size_t twklen, unsigned int radix);
//    WBCRYPTO_fpe_context *WBCRYPTO_co_wbsm4_dec_ee_fpe_init(WBCRYPTO_co_wbsm4_dec_ee_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_CO_WBSM4_H
