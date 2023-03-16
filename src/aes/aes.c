#include <wbcrypto/aes.h>

WBCRYPTO_aes_context *WBCRYPTO_aes_context_init(){
    struct aes_context *ctx=malloc(sizeof(struct aes_context));
    if(ctx==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_aes_context_init",WBCRYPTO_ERR_ALLOC_FAILED);
        goto cleanup;
    }
    memset(ctx,0,sizeof(struct aes_context));
    return ctx;
cleanup:
    return NULL;
}

void WBCRYPTO_aes_context_free(WBCRYPTO_aes_context *ctx){
    memset(ctx,0,sizeof(struct aes_context));
}

int WBCRYPTO_aes_init_key(WBCRYPTO_aes_context *ctx, const uint8_t *key, size_t keylen){
    keylen = keylen >= 16 ? 16 : keylen;
    uint8_t input_key[16];
    memcpy(input_key, key, keylen);
    AES_set_encrypt_key(key, 128, &ctx->aes_key);
    return 1;
}

int WBCRYPTO_aes_encrypt(const unsigned char *in, unsigned char *out, WBCRYPTO_aes_context *ctx){
    AES_encrypt(in, out, &ctx->aes_key);
    return 1;
}

int WBCRYPTO_aes_decrypt(const unsigned char *in, unsigned char *out, WBCRYPTO_aes_context *ctx){
    AES_decrypt(in, out, &ctx->aes_key);
    return 1;
}
