#ifndef HEADER_FPE_LOCL_H
# define HEADER_FPE_LOCL_H

# include <openssl/bn.h>

# define FF1_ROUNDS 10
# define FF3_ROUNDS 8
# define FF3_TWEAK_SIZE 8

// ceil and floor for x / (2 ^ bit)
# define ceil2(x, bit) ( ((x) >> (bit)) + ( ((x) & ((1 << (bit)) - 1)) > 0 ) )
# define floor2(x, bit) ( (x) >> (bit) )

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);

void map_chars(const unsigned char str[], unsigned int result[]);

void inverse_map_chars(unsigned result[], unsigned char str[], int len);

//int log2(int x);

#endif
