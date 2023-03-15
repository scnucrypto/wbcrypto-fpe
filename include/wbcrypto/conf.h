#ifndef WBCRYPTO_CONF_H
#define WBCRYPTO_CONF_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wbcrypto/error.h>
#include <wbcrypto/modes.h>
#include <wbcrypto/utils.h>
#include <wbcrypto/fpe.h>

//encryption mdoes
#define WBCRYPTO_ENCRYPT_MODE 1
#define WBCRYPTO_DECRYPT_MODE 0

//number of test cycle
#define TEST_CYCLE_NUM 1

//Indicates the path to the file to encrypt and decrypt
// #define WBCRYPTO_TEST_FIN_PATH "/mnt/f/test/test1M.txt"
// #define WBCRYPTO_TEST_FENC_PATH "/mnt/f/test/test.enc.txt"
// #define WBCRYPTO_TEST_FDEC_PATH "/mnt/f/test/test.dec.txt"
#define WBCRYPTO_TEST_FIN_PATH "F:\\test\\test1M.txt"
#define WBCRYPTO_TEST_FENC_PATH "F:\\test\\test.enc.txt"
#define WBCRYPTO_TEST_FDEC_PATH "F:\\test\\test.dec.txt"

// #define WBCRYPTO_TEST_KEY_FPATH "/mnt/f/test/key.whibox"
#define WBCRYPTO_TEST_ENC_KEY_FPATH "F:\\test\\enckey.whibox"
#define WBCRYPTO_TEST_DEC_KEY_FPATH "F:\\test\\deckey.whibox"


#endif //WBCRYPTO_CONF_H
