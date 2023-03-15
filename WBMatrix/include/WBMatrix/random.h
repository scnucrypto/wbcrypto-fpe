#ifndef WBCRYPTO_RANDOM_H
#define WBCRYPTO_RANDOM_H

#include "stdint.h"

unsigned int permuteQPR(unsigned int x);
void InitRandom(unsigned int seedBase);
unsigned int cus_random();

#endif //WBCRYPTO_RANDOM_H
