## 调用FPE格式加密

该项目支持FPE模式中的FF1和FF3格式加密，已封装完整。其中底层支持的算法分别有aes、sm4和wbsm4。

### 说明

参数说明

| 参数  | 说明                                                         |
| ----- | ------------------------------------------------------------ |
| key   | 密钥，用于底层算法的密钥输入                                 |
| tweak | 第二密钥，是key的调整参数，加大与key相互配合完成加密操作。注意：tweak取值一般取特殊意义的参数。如：输入手机号11位，取中间四位进行FF1加密，一般会将前3位和后四位组合作为tweak |
| radix | 字典表，用于规定了输出密文的范围。如有：十进制纯数字格式'0'~'9'，字母表格式'a'~'z'和'A'~'Z'等 |

### AES调用实例

```c
#include <wbcrypto/sm4.h>

int main(){
    //密钥，密钥可非16byte长度，若短于16byte长度会进行pkcs7扩充，若长于16byte会进行裁减
    const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    //密钥调整参数，可为空
    const uint8_t tweak[] = {
    };
    //输入的参数，最少为6位
    const char input[] = "0123456789";
    char cipher[10]={0};
    char plain[10]={0};
	
    //sm4结构体的初始化
    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    //初始化fpe结构体，参数：
    //已初始的aes结构体，密钥调整参数，密钥调整参数长度，radix
    //其中radix输入10表示纯数字'0'~'9'，36表示'0'~'9'和'a'~'z'组合
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_aes_fpe_init(aes_ctx, tweak, sizeof(tweak), 12);
    //ff1加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    //ff1解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    
    //ff3加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    //ff3解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
}
```

### SM4调用实例

```c
#include <wbcrypto/sm4.h>

int main(){
    //密钥，密钥可非16byte长度，若短于16byte长度会进行pkcs7扩充，若长于16byte会进行裁减
    const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    //密钥调整参数，可为空
    const uint8_t tweak[] = {
    };
    //输入的参数，最少为6位
    const char input[] = "0123456789";
    char cipher[10]={0};
    char plain[10]={0};
	
    //sm4结构体的初始化
    WBCRYPTO_sm4_context *sm4_ctx=WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    //初始化fpe结构体，参数：
    //已初始的sm4结构体，密钥调整参数，密钥调整参数长度，radix
    //其中radix输入10表示纯数字'0'~'9'，36表示'0'~'9'和'a'~'z'组合
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(aes_ctx, tweak, sizeof(tweak), 12);
    //ff1加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    //ff1解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    
    //ff3加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    //ff3解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
}
```

### wbsm4调用实例

```c
#include <wbcrypto/wbsm4.h>

int main(){
    //密钥，密钥可非16byte长度，若短于16byte长度会进行pkcs7扩充，若长于16byte会进行裁减
    const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    //密钥调整参数，可为空
    const uint8_t tweak[] = {
    };
    //输入的参数，最少为6位
    const char input[] = "0123456789";
    char cipher[10]={0};
    char plain[10]={0};
	
    //wbsm4结构体的初始化，具体初始化方法参考call-wbsm4.md
    WBCRYPTO_wbsm4_context *wbsm4_ctx=WBCRYPTO_wbsm4_context_init(1, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    //初始化fpe结构体，参数：
    //已初始的wbsm4结构体，密钥调整参数，密钥调整参数长度，radix
    //其中radix输入10表示纯数字'0'~'9'，36表示'0'~'9'和'a'~'z'组合
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(aes_ctx, tweak, sizeof(tweak), 12);
    //ff1加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    //ff1解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    
    //ff3加密，参数：已初始的fpe结构体，输入，密文
    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    //ff3解密，参数：已初始的fpe结构体，密文，明文
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
}
```

