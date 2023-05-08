#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>
#include <ctype.h>
#include "utf8_util.h"

int aux_fpe_name(WBCRYPTO_fpe_app_context *ctx, char *name, char *after_name, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(name) / 3;
    int i, tweak_len = 0;

    if (len == 4) {
        tweak_len = 2;
    }else if(len == 3 || len ==2){
        tweak_len = 1;
    }
    char input[(len - tweak_len) * 4 + 1];
    char tweak[tweak_len * 4 + 1];
    char ans[(len - tweak_len) * 4];
    char *input_p = input;
    char *tweak_p = tweak;
    char *ch = name;
    for (i = 0; i < tweak_len; i++, ch += 3) {
        uint32_t uc = utf8CharToUint32(ch);
        int uc_int = utf8Uint32ToInt(uc);
        utf8IntToCharDuodecimal(uc_int, tweak_p);
        tweak_p += 4;
    }
    for (;i < len; i++, ch += 3) {
        uint32_t uc = utf8CharToUint32(ch);
        int uc_int = utf8Uint32ToInt(uc);
        utf8IntToCharDuodecimal(uc_int, input_p);
        input_p += 4;
    }
    input[(len - tweak_len) * 4] = '\0';
    tweak[tweak_len * 4] = '\0';

    WBCRYPTO_fpe_context *fpe_ctx = NULL;
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        fpe_ctx = WBCRYPTO_sm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else { // default: aes
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    }
    (*block)(fpe_ctx, input, ans);

    char *ori_add = name;
    char *ans_p = ans;
    char *af_p = after_name;
    for (i = 0; i < tweak_len; i++, ori_add += 3, af_p += 3) {
        memcpy(af_p, ori_add, 3);
    }
    for (; i < len; af_p += 3, i++) {
        int uc_int = utf8CharDuodecimalToInt(ans_p);
        uint32_t uc = utf8IntToUint32(uc_int);
        utf8Uint32ToChar(uc, af_p);
        ans_p += 4;
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_name(WBCRYPTO_fpe_app_context *ctx, char *name, char *after_name) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    }
    return aux_fpe_name(ctx, name, after_name, block);
}

int WBCRYPTO_fpe_decrypt_name(WBCRYPTO_fpe_app_context *ctx, char *name, char *after_name) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    }
    return aux_fpe_name(ctx, name, after_name, block);
}