#ifndef WBCRYPTO_TEST_LOCAL_H
#define WBCRYPTO_TEST_LOCAL_H

#include <wbcrypto/conf.h>

#ifdef __cplusplus
extern "C" {
#endif

    //test util
    //print string in hexadecimal
    void TEST_print_state(unsigned char * in, size_t len);
    //compare two values, and return 1 if correct and 0 if error
    int TEST_cmp_values(char *value1, char *value2);

    int test_fpe();

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_TEST_LOCAL_H
