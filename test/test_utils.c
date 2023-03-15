#include "test_local.h"

void TEST_print_state(unsigned char * in, size_t len){
    int i;
    for(i = 0; i < len; i++) {
        printf("%.2X ", in[i]);
        if((i+1)%16==0) {
            printf("\n");
        }
    }
    printf("\n");
}