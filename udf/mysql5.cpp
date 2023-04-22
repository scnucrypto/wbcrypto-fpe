#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <wbcrypto/fpe_app.h>

const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

extern "C" {
    my_bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void fpe_deinit(UDF_INIT *initid);
    char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

/*
 * fpe(plain, mode, sample)
 * fpe(plain, phone/idcard/address)
 * fpe(plain, phone/idcard/address, "*********")
 */
my_bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count < 2 || args->arg_count > 3) {
        strcpy(message, "requires two or three argument");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT) {
        strcpy(message, "requires string as argument");
        return 1;
    }

    if (args->arg_count == 3) {
        if (args->arg_type[2] != STRING_RESULT) {
            strcpy(message, "requires string as argument");
            return 1;
        }
    }

    initid->max_length = args->lengths[0];
    initid->maybe_null = (my_bool) (*args->maybe_null);
    initid->ptr = (char *) malloc(initid->max_length + 1);
    if (initid->ptr == NULL) {
        strcpy(message, "could't allocate memory");
        return 1;
    }

    return 0;
}

void fpe_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    char *plain = args->args[0];
    char *mode = args->args[1];
    char *sample;
    int plain_len = args->lengths[0];

    if (args->arg_count == 3) {
        sample = args->args[2];
    }

    memcpy(initid->ptr, plain, plain_len);
    initid->ptr[plain_len] = '\0';

    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), "sm4", "ff1");

    if (strcmp(mode, "phone") == 0) {
        if (plain_len != 11) {
            strcpy(error, "the length of phone should be 11");
            return NULL;
        }
        if (args->arg_count == 3) {
            WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_phone(&app_ctx, plain, initid->ptr);
        }
    } else if (strcmp(mode, "idcard") == 0) {
        if (plain_len != 18) {
            strcpy(error, "the length of id-card should be 18");
            return NULL;
        }
        if (args->arg_count == 3) {
            WBCRYPTO_fpe_encrypt_idcard_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_idcard(&app_ctx, plain, initid->ptr);
        }
    } else if (strcmp(mode, "name") == 0 || strcmp(mode, "address") == 0) {
        if (args->arg_count == 3) {
            WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_cn_utf8(&app_ctx, plain, initid->ptr);
        }
    } else {
        strcpy(error, "requires optional mode: phone or idcard or address");
        return NULL;
    }

    *length = plain_len;
    memcpy(result, initid->ptr, plain_len);

    // char ret[1024];
    // sprintf(ret, "%s", result);

    return result;
}