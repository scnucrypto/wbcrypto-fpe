#ifndef WBCRYPTO_UTILS_H
#define WBCRYPTO_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wbcrypto/error.h>

#define WBCRYPTO_PADDING_NUM 16

/**
 * expand or reduce the key with #pkcs7 standard
 * expand: using PKCS#7 for key expansion
 * reduce: delete bits larger than 16byte
 * @param src initial key
 * @param srclen initial key length
 * @param dst padding key, must be init
 * @return padding key length
 */
size_t WBCRYPTO_key_padding_pkcs7(const unsigned char *src, size_t srclen, unsigned char *dst);

/**
 * expand or reduce the key
 * expand: using zero for expansion
 * reduce: delete bits larger than 16byte
 * @param src initial key
 * @param srclen initial key length
 * @param dst padding key, must be init
 * @return padding key length
 */
size_t WBCRYPTO_key_padding_zeros(const unsigned char *src, size_t srclen, unsigned char *dst);

/**
 * expand the msg with #pkcs7 standard
 * @param src msg
 * @param srclen msg length
 * @param dst padding msg, must be init
 * @return padding msg length
 */
size_t WBCRYPTO_padding_pkcs7_merge(unsigned char *src, size_t srclen, unsigned char *dst);

/**
 * expand the msg with #pkcs7 standard, return the expand length
 * @param src msg
 * @param srclen msg length
 * @return padding msg length
 */
size_t WBCRYPTO_padding_pkcs7_merge_length(unsigned char *src, size_t srclen);

/**
 * remove the msg with #pkcs7 expand, return the removed length
 * @param src expanded msg
 * @param srclen expanded msg length
 * @param dst removed msg, must be init
 * @return removed msg length
 */
size_t WBCRYPTO_padding_pkcs7_separate(unsigned char *src, size_t srclen, unsigned char *dst);

/**
 * remove the expanded msg with #pkcs7 expand, return the removed length
 * @param src expanded msg
 * @param srclen expanded msg length
 * @return removed msg length
 */
size_t WBCRYPTO_padding_pkcs7_separate_length(unsigned char *src, size_t srclen);

/**
 * Convert key-file to context
 */
int WBCRYPTO_keystore_file_to_key(void *ctx, size_t ctx_len, char *fpath);

/**
 * Convert T-box to file for storage
 */
int WBCRYPTO_keystore_key_to_file(const void *ctx, size_t ctx_len, char *fpath);

int wRandomShuffleU8(uint8_t *list, int len);

#endif //WBCRYPTO_UTILS_H
