#include "utf8_util.h"

uint32_t utf8CharToUint32(char *str) {
    uint32_t uc;
    uint8_t byte1, byte2, byte3;
    uc = ((str[0] & 0x0f) << 12) | ((str[1] & 0x3f) << 6) | (str[2] & 0x3f);
    return uc;
}

int utf8Uint32ToChar(uint32_t uc, char *str) {
    str[0] = (uc >> 12) | 0xe0;         // 取最高8位
    str[1] = ((uc >> 6) & 0x3f) | 0x80; // 取次高8位
    str[2] = (uc & 0x3f) | 0x80;        // 取次低8位
    return 0;
}

int utf8Uint32ToInt(uint32_t uc) {
    return uc - 0x4E00;
}

uint32_t utf8IntToUint32(int uc) {
    return uc + 0x4E00;
}

//void utf8IntToCharNum(int uc, char *num) {
//    for (int i = 0; i < 5; i++) {
//        if (uc == 0) {
//            num[i] = '0';
//            continue;
//        }
//        num[i] = (uc % 10) + '0';
//        uc /= 10;
//    }
//}
//
//int utf8CharNumToInt(char *num) {
//    int ret = 0, ten = 1;
//    for (int i = 0; i < 5; i++) {
//        ret += (num[i] - '0') * ten;
//        ten *= 10;
//    }
//    return ret;
//}

int char_to_int(char c) {
    if (isdigit(c)) {
        return c - '0';
    } else if (isupper(c)) {
        return c - 'A' + 10;
    } else if (islower(c)) {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

void utf8IntToCharDuodecimal(int dec, char result[]) {
    if (dec > 20735 || dec < 0) {
        printf("Error: invalid duodecimal number: %d", dec);
        return;
    }
    int i = 0, num = dec;
    while (num > 0) {
        int remainder = num % 12;
        if (remainder < 10) {
            result[i] = '0' + remainder;
        } else {
            result[i] = 'a' + remainder - 10;
        }
        num /= 12;
        i++;
    }
    while (i <= 4) {
        result[i++] = '0';
    }
}

int utf8CharDuodecimalToInt(const char duo[]) {
    int len = strlen(duo);
    if (len < 3) {
        printf("Error: invalid duodecimal number!");
        return 0;
    }
    int i;
    int result = 0;
    for (i = 3; i >= 0; i--) {
        int value = char_to_int(duo[i]);
        if (value == -1 || value >= 12) {
            printf("Error: invalid duodecimal number");
            return 0;
        }
        result = (result) * 12 + value;
    }
    return result;
}