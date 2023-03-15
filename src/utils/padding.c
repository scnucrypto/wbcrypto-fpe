#include <wbcrypto/utils.h>

size_t WBCRYPTO_key_padding_pkcs7(const unsigned char *src, size_t srclen, unsigned char *dst){
    int i, pad_num;
    dst = (unsigned char *)realloc(dst,WBCRYPTO_PADDING_NUM*sizeof(unsigned char));
    memset(dst, 0, WBCRYPTO_PADDING_NUM*sizeof(unsigned char));
    if(srclen>WBCRYPTO_PADDING_NUM){
        for(i=0;i<WBCRYPTO_PADDING_NUM;i++) {
            dst[i] = src[i];
        }
    }else{
        for(i=0;i<srclen;i++) {
            dst[i] = src[i];
        }
        if(srclen<WBCRYPTO_PADDING_NUM){
            pad_num=WBCRYPTO_PADDING_NUM-srclen;
            for(i=srclen;i<WBCRYPTO_PADDING_NUM;i++){
                dst[i]=pad_num;
            }
        }
    }
    return WBCRYPTO_PADDING_NUM;
}

size_t WBCRYPTO_key_padding_zeros(const unsigned char *src, size_t srclen, unsigned char *dst){
    int i;
    dst = (unsigned char *)realloc(dst,WBCRYPTO_PADDING_NUM*sizeof(unsigned char));
    memset(dst, 0, WBCRYPTO_PADDING_NUM*sizeof(unsigned char));
    if(srclen>WBCRYPTO_PADDING_NUM){
        for(i=0;i<WBCRYPTO_PADDING_NUM;i++) {
            dst[i] = src[i];
        }
    }else{
        for(i=0;i<srclen;i++) {
            dst[i] = src[i];
        }
        if(srclen<WBCRYPTO_PADDING_NUM){
            for(i=srclen;i<WBCRYPTO_PADDING_NUM;i++){
                dst[i]=0;
            }
        }
    }
    return WBCRYPTO_PADDING_NUM;
}

size_t WBCRYPTO_padding_pkcs7_merge(unsigned char *src, size_t srclen, unsigned char *dst){
    int i, pad_num, pad_len;
    pad_len = (srclen % 16 == 0)?srclen:((srclen/16)+1) *16;
    dst = (unsigned char *)realloc(dst, pad_len*sizeof(unsigned char));
    memset(dst, 0, pad_len*sizeof(unsigned char));
    for(i=0;i<srclen;i++) {
        dst[i] = src[i];
    }
    if(pad_len > srclen){
        pad_num = pad_len-srclen;
        for(i=srclen;i<pad_len;i++){
            dst[i]=pad_num;
        }
    }
    return pad_len;
}

size_t WBCRYPTO_padding_pkcs7_separate(unsigned char *src, size_t srclen, unsigned char *dst){
    int pad_num = (int)src[srclen-1], afpad_len;
    if(pad_num > 16 || pad_num < 0){
        pad_num = 0;
    }
    afpad_len = srclen - pad_num;
    dst = (unsigned char *)realloc(dst,afpad_len*sizeof(unsigned char));
    memcpy(dst, src, afpad_len*sizeof(unsigned char));
    return afpad_len;
}

size_t WBCRYPTO_padding_pkcs7_merge_length(unsigned char *src, size_t srclen){
    int pad_len;
    pad_len = (srclen % 16 == 0)?srclen:((srclen/16)+1) *16;
    return pad_len;
}

size_t WBCRYPTO_padding_pkcs7_separate_length(unsigned char *src, size_t srclen){
    int pad_num = src[srclen-1], afpad_len;
    if(pad_num > 16 || pad_num < 0){
        pad_num = 0;
    }
    afpad_len = srclen - pad_num;
    return afpad_len;
}

