#include <wbcrypto/modes.h>

int WBCRYPTO_cbc128_encrypt(const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t max_olen, size_t *use_olen,
                            const void *key, unsigned char ivec[16], block128_f block)
{
    int ret=0,len;
    unsigned char *afin = (unsigned char *)malloc(inlen*sizeof(unsigned char));
    len = WBCRYPTO_padding_pkcs7_merge((unsigned char *)in, inlen, afin);
    if(max_olen<len){
        WBCRYPTO_THROW_REASON("WBCRYPTO_cbc128_encrypt",WBCRYPTO_INLEN_THAN_OUTLEN);
    }
    *use_olen = len;
#ifdef IMPORT_OPENSSL
    CRYPTO_cbc128_encrypt(afin, out, len, key, ivec, block);
#else
    size_t n;
    const unsigned char *iv = ivec;

    while (len >= 16) {
        for (n = 0; n < 16; n += sizeof(size_t))
            *(size_t *)(out + n) =
                    *(size_t *)(afin + n) ^ *(size_t *)(iv + n);
        WBCRYPTO_MPI_CHK((*block) (out, out, key));
        iv = out;
        len -= 16;
        afin += 16;
        out += 16;
    }
    while (len) {
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = afin[n] ^ iv[n];
        for (; n < 16; ++n)
            out[n] = iv[n];
        WBCRYPTO_MPI_CHK((*block) (out, out, key));
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        afin += 16;
        out += 16;
    }
//    memcpy(ivec, iv, 16);
#endif
    ret=1;
cleanup:
    return ret;
}

int WBCRYPTO_cbc128_decrypt(const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t max_olen, size_t *use_olen,
                            const void *key,unsigned char ivec[16], block128_f block)
{
    int ret=0,len;
    if(max_olen<inlen){
        WBCRYPTO_THROW_REASON("WBCRYPTO_cbc128_decrypt",WBCRYPTO_INLEN_THAN_OUTLEN);
    }else{
        len=inlen;
    }
#ifdef IMPORT_OPENSSL
    CRYPTO_cbc128_decrypt(in, out, len, key, ivec, block);
#else
    size_t n;
    union {
        size_t t[16 / sizeof(size_t)];
        unsigned char c[16];
    } tmp;

    if (in != out) {
        const unsigned char *iv = ivec;

        if (16 % sizeof(size_t) == 0) { /* always true */
            while (len >= 16) {
                size_t *out_t = (size_t *)out, *iv_t = (size_t *)iv;

                WBCRYPTO_MPI_CHK((*block) (in, out, key));
                for (n = 0; n < 16 / sizeof(size_t); n++)
                    out_t[n] ^= iv_t[n];
                iv = in;
                len -= 16;
                in += 16;
                out += 16;
            }
        }
        memcpy(ivec, iv, 16);
    } else {
        if (16 % sizeof(size_t) == 0) { /* always true */
            while (len >= 16) {
                size_t c, *out_t = (size_t *)out, *ivec_t = (size_t *)ivec;
                const size_t *in_t = (const size_t *)in;

                WBCRYPTO_MPI_CHK((*block) (in, tmp.c, key));
                for (n = 0; n < 16 / sizeof(size_t); n++) {
                    c = in_t[n];
                    out_t[n] = tmp.t[n] ^ ivec_t[n];
                    ivec_t[n] = c;
                }
                len -= 16;
                in += 16;
                out += 16;
            }
        }
    }

    while (len) {
        unsigned char c;
        WBCRYPTO_MPI_CHK((*block) (in, tmp.c, key));
        for (n = 0; n < 16 && n < len; ++n) {
            c = in[n];
            out[n] = tmp.c[n] ^ ivec[n];
            ivec[n] = c;
        }
        if (len <= 16) {
            for (; n < 16; ++n)
                ivec[n] = in[n];
            break;
        }
        len -= 16;
        in += 16;
        out += 16;
    }
#endif
//    *use_olen = WBCRYPTO_padding_pkcs7_separate_length(in, inlen);
    ret=1;
cleanup:
    return ret;
}