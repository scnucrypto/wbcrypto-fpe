#include <wbcrypto/fpe_app.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>
#include "utf8_util.h"

int aux_fpe_cn(WBCRYPTO_wbsm4_context *ctx, char *cn, char *sample, char *after_cn, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(cn) / 3;
    int i, tweak_len = 0;

    for (i = 0; i < strlen(sample); i++) {
        if (sample[i] == '*') {
            ++tweak_len;
        }
    }
    if (strcmp(sample, "") != 0) {
        tweak_len = len - tweak_len;
    }
    char input[(len - tweak_len) * 4 + 1];
    char tweak[tweak_len * 4 + 1];
    char ans[(len - tweak_len) * 4];
    char *input_p = input;
    char *tweak_p = tweak;
    char *ch = cn;
    if (strcmp(sample, "") == 0) {
        for (i = 0; i < len; i++, ch += 3) {
            uint32_t uc = utf8CharToUint32(ch);
            int uc_int = utf8Uint32ToInt(uc);
            utf8IntToCharDuodecimal(uc_int, input_p);
            input_p += 4;
        }
    } else {
        for (i = 0; i < strlen(sample); ch += 3) {
            uint32_t uc = utf8CharToUint32(ch);
            int uc_int = utf8Uint32ToInt(uc);
            if (sample[i] == '*') {
                utf8IntToCharDuodecimal(uc_int, input_p);
                input_p += 4;
                ++i;
            } else {
                utf8IntToCharDuodecimal(uc_int, tweak_p);
                tweak_p += 4;
                i += 3;
            }
        }
    }
    input[(len - tweak_len) * 4] = '\0';
    tweak[tweak_len * 4] = '\0';

    WBCRYPTO_fpe_context *fpe_ctx = NULL;
    fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx, tweak, sizeof(tweak), 12);
    (*block)(fpe_ctx, input, ans);

    char *ori_add = cn;
    char *ans_p = ans;
    char *af_p = after_cn;
    if (strcmp(sample, "") == 0) {
        for (i = 0; i < len; i++, af_p += 3) {
            int uc_int = utf8CharDuodecimalToInt(ans_p);
            uint32_t uc = utf8IntToUint32(uc_int);
            utf8Uint32ToChar(uc, af_p);
            ans_p += 4;
        }
    } else {
        for (i = 0; i < strlen(sample); af_p += 3, ori_add += 3) {
            if (sample[i] == '*') {
                int uc_int = utf8CharDuodecimalToInt(ans_p);
                uint32_t uc = utf8IntToUint32(uc_int);
                utf8Uint32ToChar(uc, af_p);
                ans_p += 4;
                ++i;
            } else {
                memcpy(af_p, ori_add, 3);
                i += 3;
            }
        }
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_cn_utf8(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn) {
    return WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(ctx, cn, after_cn, "");
}

int WBCRYPTO_fpe_decrypt_cn_utf8(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn) {
    return WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(ctx, cn, after_cn, "");
}

int WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn, char *sample) {
    fpe_block128_f block;
    block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    return aux_fpe_cn(ctx, cn, sample, after_cn, block);
}

int WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(WBCRYPTO_wbsm4_context *ctx, char *cn, char *after_cn, char *sample) {
    fpe_block128_f block;
    block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    return aux_fpe_cn(ctx, cn, sample, after_cn, block);
}