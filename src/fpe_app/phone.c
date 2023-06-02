#include <wbcrypto/fpe_app.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>

int aux_fpe_phone(WBCRYPTO_wbsm4_context *ctx, char *phone, char *sample, char *after_phone, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(phone);
    int i, j, k, tweak_len = 0;

    if (strcmp(sample, "") != 0) {
        for (i = 0; i < len; i++) {
            if (sample[i] != '*') {
                ++tweak_len;
            }
        }
    }
    char input[len - tweak_len + 1];
    input[len - tweak_len] = '\0';
    char tweak[tweak_len + 1];
    tweak[tweak_len] = '\0';
    char ans[len - tweak_len];
    for (i = 0, j = 0, k = 0; i < len; i++) {
        if (strcmp(sample, "") != 0 && sample[i] != '*') {
            tweak[k++] = phone[i];
        } else {
            input[j++] = phone[i];
        }
    }

    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx, tweak, sizeof(tweak), 10);
    (*block)(fpe_ctx, input, ans);

    for (i = 0, j = 0; i < len; i++) {
        if (strcmp(sample, "") != 0 && sample[i] != '*') {
            after_phone[i] = phone[i];
        } else {
            after_phone[i] = ans[j++];
        }
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_phone(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone) {
    return WBCRYPTO_fpe_encrypt_phone_with_sample(ctx, phone, after_phone, "");
}

int WBCRYPTO_fpe_decrypt_phone(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone) {
    return WBCRYPTO_fpe_decrypt_phone_with_sample(ctx, phone, after_phone, "");
}

int WBCRYPTO_fpe_encrypt_phone_with_sample(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone, char *sample) {
    fpe_block128_f block;
    block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}

int WBCRYPTO_fpe_decrypt_phone_with_sample(WBCRYPTO_wbsm4_context *ctx, char *phone, char *after_phone, char *sample) {
    fpe_block128_f block;
    block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}