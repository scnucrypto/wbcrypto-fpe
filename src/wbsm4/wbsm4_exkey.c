#include "wbsm4_local.h"

int WBCRYPTO_wbsm4_key2file(const WBCRYPTO_wbsm4_context *ctx, char *fpath) {
    int ret = 0;
    FILE *wkey;
    int i, j, k, l;

    if ((wkey = fopen(fpath, "wb+")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_FILE_IO);
    }
    fputs("XL-WBSM4", wkey);
    if (!fwrite(&ctx->encmode, sizeof(int), 1, wkey)) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
    }
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 3; j++) {
            for (k = 0; k < 4; k++) {
                for (l = 0; l < 256; l++) {
                    if (!fwrite(&ctx->MM[i][j][k][l], sizeof(uint32_t), 1, wkey)) {
                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
                    }
                }
            }
        }
    }
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 4; j++) {
            for (k = 0; k < 256; k++) {
                if (i < 4) {
                    if (!fwrite(&ctx->SE[i][j][k], sizeof(uint32_t), 1, wkey)
                        || !fwrite(&ctx->FE[i][j][k], sizeof(uint32_t), 1, wkey)) {
                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
                    }
                }
                if (!fwrite(&ctx->CC[i][j][k], sizeof(uint32_t), 1, wkey)
                    || !fwrite(&ctx->DD[i][j][k], sizeof(uint32_t), 1, wkey)
                    || !fwrite(&ctx->Table[i][j][k], sizeof(uint32_t), 1, wkey)) {
                    WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_key2file", WBCRYPTO_ERR_READ_BAD_FILE);
                }
            }
        }
    }
    ret = 1;
cleanup:
    fclose(wkey);
    return ret;
}

int WBCRYPTO_wbsm4_file2key(WBCRYPTO_wbsm4_context *ctx, char *fpath) {
    int ret = 0;
    FILE *rkey;
    int i, j, k, l;

    if ((rkey = fopen(fpath, "rb")) == NULL) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_FILE_IO);
    }
    char algname[17];
    memset(algname, 0, sizeof(algname));
    fgets(algname, 17, rkey);
    if (strcmp(algname, "XL-WBSM4") != 0) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
    }
    if (!fread(&ctx->encmode, sizeof(int), 1, rkey)) {
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
    }
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 3; j++) {
            for (k = 0; k < 4; k++) {
                for (l = 0; l < 256; l++) {
                    if (!fread(&ctx->MM[i][j][k][l], sizeof(uint32_t), 1, rkey)) {
                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
                    }
                }
            }
        }
    }
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 4; j++) {
            for (k = 0; k < 256; k++) {
                if (i < 4) {
                    if (!fread(&ctx->SE[i][j][k], sizeof(uint32_t), 1, rkey)
                        || !fread(&ctx->FE[i][j][k], sizeof(uint32_t), 1, rkey)) {
                        WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
                    }
                }
                if (!fread(&ctx->CC[i][j][k], sizeof(uint32_t), 1, rkey)
                    || !fread(&ctx->DD[i][j][k], sizeof(uint32_t), 1, rkey)
                    || !fread(&ctx->Table[i][j][k], sizeof(uint32_t), 1, rkey)) {
                    WBCRYPTO_THROW_REASON("WBCRYPTO_wbsm4_file2key", WBCRYPTO_ERR_READ_BAD_FILE);
                }
            }
        }
    }
    ret = 1;
cleanup:
    fclose(rkey);
    return ret;
}


