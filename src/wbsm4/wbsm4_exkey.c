#include "wbsm4_local.h"

/************第一种实现方法***************/
int WBCRYPTO_wbsm4_file2key(WBCRYPTO_wbsm4_context *ctx, char *fpath) {
    int ret = 0;
    FILE *rkey;

    if ((rkey = fopen(fpath, "rb")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_FILE_IO);
    }
    fread(ctx, sizeof(WBCRYPTO_wbsm4_context), 1, rkey);
    ret = 1;
cleanup:
    fclose(rkey);
    return ret;
}

int WBCRYPTO_wbsm4_key2file(const WBCRYPTO_wbsm4_context *ctx, char *fpath) {
    int ret = 0;
    FILE *wkey;

    if ((wkey = fopen(fpath, "wb+")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_FILE_IO);
    }
    fwrite(ctx, sizeof(WBCRYPTO_wbsm4_context), 1, wkey);
    ret = 1;
cleanup:
    fclose(wkey);
    return ret;
}

/************第二种实现方法***************/
//int WBCRYPTO_wbsm4_key2file(const WBCRYPTO_wbsm4_context *ctx, char *fpath) {
//    int ret = 0;
//    FILE *wkey;
//    int i, j, k, l;
//
//    if ((wkey = fopen(fpath, "wb+")) == NULL) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_FILE_IO);
//    }
//    if (!fwrite(&ctx->encmode, sizeof(int), 1, wkey)) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
//    }
//    for (i = 0; i < 32; i++) {
//        for (j = 0; j < 3; j++) {
//            for (k = 0; k < 4; k++) {
//                for (l = 0; l < 256; l++) {
//                    if (!fwrite(&ctx->MM[i][j][k][l], sizeof(uint32_t), 1, wkey)) {
//                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
//                    }
//                }
//            }
//        }
//    }
//    for (i = 0; i < 32; i++) {
//        for (j = 0; j < 4; j++) {
//            for (k = 0; k < 256; k++) {
//                if (i < 4) {
//                    if (!fwrite(&ctx->SE[i][j][k], sizeof(uint32_t), 1, wkey)
//                        || !fwrite(&ctx->FE[i][j][k], sizeof(uint32_t), 1, wkey)) {
//                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
//                    }
//                }
//                if (!fwrite(&ctx->CC[i][j][k], sizeof(uint32_t), 1, wkey)
//                    || !fwrite(&ctx->DD[i][j][k], sizeof(uint32_t), 1, wkey)
//                    || !fwrite(&ctx->Table[i][j][k], sizeof(uint32_t), 1, wkey)) {
//                    WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
//                }
//            }
//        }
//    }
//    ret = 1;
//cleanup:
//    fclose(wkey);
//    return ret;
//}

//int WBCRYPTO_wbsm4_file2key(WBCRYPTO_wbsm4_context *ctx, char *fpath) {
//    int ret = 0;
//    FILE *rkey;
//    int i, j, k, l;
//    if ((rkey = fopen(fpath, "rb")) == NULL) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_FILE_IO);
//    }
//    if (!fread(&ctx->encmode, sizeof(int), 1, rkey)) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
//        goto cleanup;
//    }
//    uint32_t buffer[32][3][4][256];
//    if (!fread(buffer, sizeof(uint32_t), 32 * 3 * 4 * 256, rkey)) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
//        goto cleanup;
//    }
//    for (i = 0; i < 32; i++) {
//        for (j = 0; j < 3; j++) {
//            for (k = 0; k < 4; k++) {
//                for (l = 0; l < 256; l++) {
//                    ctx->MM[i][j][k][l] = buffer[i][j][k][l];
//                }
//            }
//        }
//    }
//    uint32_t buffer2[32][4][256];
//    if (!fread(buffer2, sizeof(uint32_t), 32 * 4 * 256, rkey)) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
//        goto cleanup;
//    }
//    for (i = 0; i < 32; i++) {
//        for (j = 0; j < 4; j++) {
//            for (k = 0; k < 256; k++) {
//                if (i < 4) {
//                    ctx->SE[i][j][k] = buffer2[i][j][k];
//                    ctx->FE[i][j][k] = buffer2[i + 4][j][k];
//                }
//                ctx->CC[i][j][k] = buffer2[i][j][k];
//                ctx->DD[i][j][k] = buffer2[i + 8][j][k];
//                ctx->Table[i][j][k] = buffer2[i + 12][j][k];
//            }
//        }
//    }
//    ret = 1;
//cleanup:
//    fclose(rkey);
//    return ret;
//}

/************第三种实现方法***************/
//int WBCRYPTO_wbsm4_key2file(const WBCRYPTO_wbsm4_context *ctx, char *fpath) {
//    int ret = 0;
//    FILE *file = fopen(fpath, "wb");
//    if (file == NULL) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_FILE_IO);
//    }
//    fwrite(&ctx->encmode, sizeof(int), 1, file);
//    fwrite(ctx->MM, sizeof(uint32_t), 32 * 3 * 4 * 256, file);
//    fwrite(ctx->SE, sizeof(uint32_t), 32 * 4 * 256, file);
//    fwrite(ctx->FE, sizeof(uint32_t), 32 * 4 * 256, file);
//    fwrite(ctx->CC, sizeof(uint32_t), 32 * 4 * 256, file);
//    fwrite(ctx->DD, sizeof(uint32_t), 32 * 4 * 256, file);
//    fwrite(ctx->Table, sizeof(uint32_t), 32 * 4 * 256, file);
//    ret = 1;
//cleanup:
//    fclose(file);
//    return ret;
//}

//int WBCRYPTO_wbsm4_file2key(WBCRYPTO_wbsm4_context *ctx, char *fpath) {
//    int ret = 0;
//    FILE *file = fopen(fpath, "rb");
//    if (file == NULL) {
//        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_FILE_IO);
//    }
//    fread(&ctx->encmode, sizeof(int), 1, file);
//    fread(ctx->MM, sizeof(uint32_t), 32 * 3 * 4 * 256, file);
//    fread(ctx->SE, sizeof(uint32_t), 32 * 4 * 256, file);
//    fread(ctx->FE, sizeof(uint32_t), 32 * 4 * 256, file);
//    fread(ctx->CC, sizeof(uint32_t), 32 * 4 * 256, file);
//    fread(ctx->DD, sizeof(uint32_t), 32 * 4 * 256, file);
//    fread(ctx->Table, sizeof(uint32_t), 32 * 4 * 256, file);
//    ret = 1;
//cleanup:
//    fclose(file);
//    return ret;
//}
