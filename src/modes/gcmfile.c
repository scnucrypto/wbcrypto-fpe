#include <wbcrypto/modes.h>

WBCRYPTO_gcmfile_context *WBCRYPTO_gcmfile_init( void *key, block128_f block){
    struct gcmfile_context *ctx=malloc(sizeof(struct gcmfile_context));
    if(ctx==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_init",WBCRYPTO_ERR_ALLOC_FAILED);
    }
    memset(ctx->tag, 0, sizeof(WBCRYPTO_GCM_FILE_TAG_LEN));
    ctx->gcm=WBCRYPTO_gcm_init(key, block);
    return ctx;
cleanup:
    return NULL;
}

int WBCRYPTO_gcmfile_setiv(WBCRYPTO_gcmfile_context *ctx,
                           const unsigned char *iv, size_t len){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_gcm_setiv(ctx->gcm, iv, len)
    );
    ret=1;
    cleanup:
    return ret;
}

int WBCRYPTO_gcmfile_aad(WBCRYPTO_gcmfile_context *ctx,
                         const unsigned char *aad, size_t len){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_gcm_aad(ctx->gcm, aad, len)
    );
    ret=1;
    cleanup:
    return ret;
}

int WBCRYPTO_gcmfile_encrypt(WBCRYPTO_gcmfile_context *ctx,
                             char *infpath, char *outfpath){
    int ret=0;
    int len_outfpath, file_size, block_size;
    FILE *infp, *tmpfp, *outfp;

    // #0 Open file
    len_outfpath = strlen(outfpath);
    char *tmp_file_path = (char *)malloc((len_outfpath + 5) * sizeof(char));
    memcpy(tmp_file_path, outfpath, len_outfpath);
    memcpy(tmp_file_path + len_outfpath, ".tmp", 5);

    if ((infp = fopen(infpath, "rb")) == NULL)
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_encrypt",WBCRYPTO_ERR_FILE_IO);
    if ((tmpfp = fopen(tmp_file_path, "wb+")) == NULL)
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_encrypt",WBCRYPTO_ERR_FILE_IO);
    if ((outfp = fopen(outfpath, "wb+")) == NULL)
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_encrypt",WBCRYPTO_ERR_FILE_IO);

    // #1 Encrypt file (slice blocks)
    unsigned char buf[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
    unsigned char out[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
    unsigned char size_buf[sizeof(size_t)];
    memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);

    // Get size of file
    fseek(infp, 0, SEEK_END);
    file_size = ftell(infp);
    memset(size_buf, 0, sizeof(size_t));
    memcpy(size_buf, &file_size, sizeof(size_t));
    fseek(infp, 0, SEEK_SET);

    // GCM Block encrypt
    while (
            (block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, infp)) &&
            block_size != 0
            ) {
        WBCRYPTO_gcm_encrypt(ctx->gcm, buf, block_size, out, block_size);
        fwrite(out, sizeof(unsigned char), block_size, tmpfp);

        memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
        memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    }

    // Get Tag of GCM encrypt
    WBCRYPTO_gcm_finish(ctx->gcm, ctx->tag, WBCRYPTO_GCM_FILE_TAG_LEN);

    // Finish encrypt
    fflush(tmpfp);
    fseek(tmpfp, 0, SEEK_SET);
    fclose(infp);

    // #2 Write cipher file
    // add tag
    fwrite(&ctx->tag, sizeof(unsigned char), WBCRYPTO_GCM_FILE_TAG_LEN, outfp);
    // add file len
    fwrite(size_buf, sizeof(unsigned char), sizeof(size_t), outfp);
    // copy cipher
    memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    while (
        (block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, tmpfp)) &&
        block_size != 0
        ) {
        fwrite(buf, sizeof(unsigned char), block_size, outfp);
        memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    }

    ret=1;
cleanup:
    fclose(tmpfp);
    fclose(outfp);
    remove(tmp_file_path);
    free(tmp_file_path);
    return ret;
}

int WBCRYPTO_gcmfile_decrypt(WBCRYPTO_gcmfile_context *ctx,
                             char *infpath, char *outfpath){
    int ret=0;
    int file_size = 0, read_size = 0, block_size;
    unsigned char size_buf[sizeof(size_t)];
    FILE *infp, *outfp;

    if ((infp = fopen(infpath, "rb")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_decrypt",WBCRYPTO_ERR_NULL_PARAM);
    }

    char flag[WBCRYPTO_GCM_FILE_TAG_LEN + 1];
    memset(flag, 0, sizeof(flag));

    //read tag
    if (fread(ctx->tag, sizeof(unsigned char), WBCRYPTO_GCM_FILE_TAG_LEN, infp) == 0) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_decrypt",WBCRYPTO_ERR_ENCFILE_MODEIFIED);
    }

    memset(size_buf, 0, sizeof(size_t));
    // read real length
    if (fread(size_buf, sizeof(unsigned char), sizeof(size_t), infp) == 0) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_decrypt",WBCRYPTO_ERR_FILE_SIZE_WRONG);
    }
    file_size = (int) ((((size_buf[3] & 0xff) << 24)
                        | ((size_buf[2] & 0xff) << 16) | ((size_buf[1] & 0xff) << 8)
                        | ((size_buf[0] & 0xff) << 0)));

    // Write Plaintext
    if ((outfp = fopen(outfpath, "wb+")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_decrypt",WBCRYPTO_ERR_FILE_IO);
    }

    unsigned char buf[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
    unsigned char out[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
    memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    WBCRYPTO_gcm_finish(ctx->gcm, ctx->tag, WBCRYPTO_GCM_FILE_TAG_LEN);

    while (
            (block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, infp)) &&
            block_size != 0
            ) {
        WBCRYPTO_gcm_decrypt(ctx->gcm, buf, block_size, out, block_size);
        read_size += block_size;
        fwrite(out, sizeof(unsigned char), block_size, outfp);

        memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
        memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
    }

    fflush(outfp);
    // Invalid file
    if (read_size != file_size) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcmfile_decrypt",WBCRYPTO_ERR_FILE_SIZE_WRONG);
    }

    ret=1;
cleanup:
    fclose(infp);
    fclose(outfp);
    return ret;
}

void WBCRYPTO_gcmfile_free(WBCRYPTO_gcmfile_context *ctx){
    memset(ctx, 0, sizeof(WBCRYPTO_gcmfile_context));
}

