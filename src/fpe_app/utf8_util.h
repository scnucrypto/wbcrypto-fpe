#ifndef WBCRYPTO_FPE_UTF8_UTIL_H
#define WBCRYPTO_FPE_UTF8_UTIL_H

#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

uint32_t utf8CharToUint32(char *str);

int utf8Uint32ToChar(uint32_t uc, char *str);

int utf8Uint32ToInt(uint32_t uc);

uint32_t utf8IntToUint32(int uc);

//void utf8IntToCharNum(int uc, char *num);
//
//int utf8CharNumToInt(char *num);

void utf8IntToCharDuodecimal(int dec, char result[]);

int utf8CharDuodecimalToInt(const char duo[]);

#endif //WBCRYPTO_FPE_UTF8_UTIL_H
