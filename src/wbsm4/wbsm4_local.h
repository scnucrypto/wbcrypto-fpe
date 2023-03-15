#ifndef WBCRYPTO_WBSM4_LOCAL_H
#define WBCRYPTO_WBSM4_LOCAL_H

#include <wbcrypto/wbsm4.h>

#define GET32(pc)  (					\
	((uint32_t)(pc)[0] << 24) ^			\
	((uint32_t)(pc)[1] << 16) ^			\
	((uint32_t)(pc)[2] <<  8) ^			\
	((uint32_t)(pc)[3]))

#define PUT32(st, ct)					\
	(ct)[0] = (uint8_t)((st) >> 24);		\
	(ct)[1] = (uint8_t)((st) >> 16);		\
	(ct)[2] = (uint8_t)((st) >>  8);		\
	(ct)[3] = (uint8_t)(st)

extern const uint8_t SBOX[256];

#endif //WBCRYPTO_WBSM4_LOCAL_H
