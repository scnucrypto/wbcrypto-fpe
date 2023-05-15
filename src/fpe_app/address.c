#include <wbcrypto/fpe_app.h>
#include <string.h>

const char district[]= "省市区镇乡旗县村";

int WBCRYPTO_fpe_encrypt_address(WBCRYPTO_fpe_app_context *ctx, char *address, char *after_address) {
    char sample[strlen(address)];
    char *sample_p = sample;
    for (int i = 0; i < strlen(address); i+=3) {
        int flag = 1;
        for (int j = 0; j < strlen(district); j+=3) {
            if (strcmp(address[i], district[j])) {
                *sample_p = '*';
                ++sample_p;
                flag = 0;
                break;
            }
        }
        if(flag){
            *sample_p = address[i];
            ++sample_p;
            *sample_p = address[i+1];
            ++sample_p;
            *sample_p = address[i+2];
            ++sample_p;
        }
    }
    return WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(ctx, address, after_address, sample);
}

int WBCRYPTO_fpe_decrypt_address(WBCRYPTO_fpe_app_context *ctx, char *address, char *after_address) {

}