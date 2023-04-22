## 调用FPE能力接口

该项目支持手机号（11位）、身份证号（18位），utf-中文字符的FPE加解密接口

### 手机号调用实例

```c
#include <wbcrypto/fpe_app.h>

int main(){
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    // 输入手机号
    const char input[] = "13888888888";
    // 输入手机号需要加密的格式，****部分进行加密
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};

    // 初始化fpe
    WBCRYPTO_fpe_app_context app_ctx;
    // 除WBCYRPTO_FPE_CIPHER_SM4，可选：WBCYRPTO_FPE_CIPHER_AES、WBCYRPTO_FPE_CIPHER_WBSM4
    // 除WBCYRPTO_FPE_FFX_FF1，可选：WBCYRPTO_FPE_FFX_FF3
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    // 全位加密手机号
    WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    // 全位解密手机号
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    // 根据sample样式加密手机号
    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    // 全位解密手机号
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}
```

### 身份证号调用实例

```c
#include <wbcrypto/fpe_app.h>

int main(){
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    // 输入身份证号
    const char input[] = "40000000000000000X";
    // 输入身份证号需要加密的格式，****部分进行加密
    const char sample[] = "4412**********1234";
    char cipher[20] = {0};
    char plain[20] = {0};

    // 初始化fpe
    WBCRYPTO_fpe_app_context app_ctx;
    // 除WBCYRPTO_FPE_CIPHER_SM4，可选：WBCYRPTO_FPE_CIPHER_AES、WBCYRPTO_FPE_CIPHER_WBSM4
    // 除WBCYRPTO_FPE_FFX_FF1，可选：WBCYRPTO_FPE_FFX_FF3
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    // 全位加密身份证号
    WBCRYPTO_fpe_encrypt_idcard(&app_ctx, input, cipher);
    printf("[FPE idcard] encrypt answer: %s\n", cipher);
    // 全位解密身份证号
    WBCRYPTO_fpe_decrypt_idcard(&app_ctx, cipher, plain);
    printf("[FPE idcard] decrypt answer: %s\n", plain);

    // 根据sample样式加密身份证号
    WBCRYPTO_fpe_encrypt_idcard_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE idcard with sample] encrypt answer: %s\n", cipher);
    // 全位解密身份证号
    WBCRYPTO_fpe_decrypt_idcard_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE idcard with sample] decrypt answer: %s\n", plain);
}
```

### 中文字符（以地址为例）调用实例

```c
#include <wbcrypto/fpe_app.h>

int main(){
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    // 输入地址
    const char input[] = "广东省广州市天河区华南师范大学";
    // 输入地址需要加密的格式，****部分进行加密
    const char sample[] = "**省**市**区*****";
    char cipher[100] = {0};
    char plain[100] = {0};

    // 初始化fpe
    WBCRYPTO_fpe_app_context app_ctx;
    // 除WBCYRPTO_FPE_CIPHER_SM4，可选：WBCYRPTO_FPE_CIPHER_AES、WBCYRPTO_FPE_CIPHER_WBSM4
    // 除WBCYRPTO_FPE_FFX_FF1，可选：WBCYRPTO_FPE_FFX_FF3
    WBCRYPTO_fpe_app_init(&app_ctx, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    // 全位加密地址
    WBCRYPTO_fpe_encrypt_cn_utf8(&app_ctx, input, cipher);
    printf("[FPE idcard] encrypt answer: %s\n", cipher);
    // 全位解密地址
    WBCRYPTO_fpe_decrypt_cn_utf8(&app_ctx, cipher, plain);
    printf("[FPE idcard] decrypt answer: %s\n", plain);

    // 根据sample样式加密地址
    WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE idcard with sample] encrypt answer: %s\n", cipher);
    // 全位解密地址
    WBCRYPTO_fpe_decrypt_cn_utf8_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE idcard with sample] decrypt answer: %s\n", plain);
}
```

