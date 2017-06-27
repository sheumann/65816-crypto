#include <stdio.h>

#include "aes.h"

void print_hexbytes(char *prefix, unsigned char *data, unsigned int n) {
    int i;
    
    printf("%s", prefix);
    for (i = 0; i < n; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(void) {
    int i;
    struct aes_state aes_state = {
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0},
        aes_keysize_128,
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
    };
    
    print_hexbytes("Input:        ", aes_state.data, 16);
    print_hexbytes("Key:          ", aes_state.key, 16);
    
    aes_expandkey128(&aes_state);
    
    for (i = 1; i <= 10; i++) {
        printf("Round key %2i: ", i);
        print_hexbytes("", aes_state.key + i*16, 16);
    }
    
    aes_encrypt(&aes_state);
    
    print_hexbytes("Output:       ", aes_state.data, 16);
}
