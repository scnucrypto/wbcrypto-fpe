/*
 * @Author: Weijie Li
 * @Date: 2018-11-12 19:16:04
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2018-11-12 20:49:44
 */
#include <wbcrypto/utils.h>
#include <time.h>

char* wRandFuncVersion()
{
    return "default rand() function";
}

static int inited = 0;

uint32_t wRand31() {
    if (inited==0) {
        inited = 1;
        srand(time(0));
    }
    return rand();
}

uint32_t wRand32() {
    uint32_t res = wRand31() ^ (wRand31() << 1);
    return res;
}

uint64_t wRand64() {
    uint64_t a,b,c;
    a = wRand31();
    b = wRand31();
    c = wRand31();
    uint64_t res= a ^ (b<<21) ^ (c<<42) ;
    return res;
}

// // Rand a list of Number
// static int random_rand(unsigned char *output, size_t size);

// // Rand a list of int32
// static int random_rand_int_array(int *output, int count);

// Rand a list of int32 (if ctx==NULL, then init a global ctx)
int wRandomList(int *list, int len){
    if (list == NULL)
        return -1;
    while(len--) {
        *list = wRand31();
        list++;
    }
    return 0;
}


int wRandomShuffleU8(uint8_t *list, int len) {
    int t, roundCnt, ret;
    unsigned int *randNumbers;
    randNumbers = (unsigned int *)malloc((len + 10) * sizeof(unsigned int));
    memset(randNumbers, 0, (len + 10) * sizeof(unsigned int));
    wRandomList((int*) randNumbers, len);
    while (len > 0) {
        int r = randNumbers[len] % len;
        len--;
        uint8_t tmp = *(list + len);
        *(list + len) = *(list + r);
        *(list + r) = tmp;
    }
    free(randNumbers);
    return 0;
}


