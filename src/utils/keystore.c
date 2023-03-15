#include <wbcrypto/utils.h>

int WBCRYPTO_keystore_file_to_key(void *ctx, size_t ctx_len, char *fpath){
    int ret=0;
    FILE *rkey;

    if((rkey = fopen(fpath,"rb"))==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_keystore_file_to_key",WBCRYPTO_ERR_FILE_IO);
    }
    fread(ctx , ctx_len, 1, rkey);
    ret=1;
cleanup:
    fclose(rkey);
    return ret;
}

int WBCRYPTO_keystore_key_to_file(const void *ctx, size_t ctx_len, char *fpath){
    int ret=0;
    FILE *wkey;

    if((wkey = fopen(fpath,"wb+"))==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_keystore_key_to_file",WBCRYPTO_ERR_FILE_IO);
    }
    fwrite( ctx, ctx_len, 1, wkey);
    ret=1;
cleanup:
    fclose(wkey);
    return ret;
}