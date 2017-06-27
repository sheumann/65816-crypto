#include <stdio.h>
#include <MiscTool.h>
#include <Memory.h>
#include <orca.h>

#include "aes.h"

void print_hexbytes(char *prefix, unsigned char *data, unsigned int n) {
    int i;
    
    printf("%s", prefix);
    for (i = 0; i < n; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void aes128_test(void) {
    int i;
    struct aes_state aes_state = {
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
    };
    
    print_hexbytes("Input:        ", aes_state.data, 16);
    print_hexbytes("Key:          ", aes_state.key, 16);
    
    aes_expandkey128(&aes_state);

#ifdef PRINT_ROUND_KEYS
    for (i = 1; i <= 10; i++) {
        printf("Round key %2i: ", i);
        print_hexbytes("", aes_state.key + i*16, 16);
    }
#endif
    
    aes_encrypt(&aes_state);
    
    print_hexbytes("Output:       ", aes_state.data, 16);
    
    aes128_decrypt(&aes_state);
    
    print_hexbytes("Decrypted:    ", aes_state.data, 16);   
}

void aes192_test(void) {
    int i;
    struct aes_state aes_state = {
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17}
    };
    
    print_hexbytes("Input:        ", aes_state.data, 16);
    print_hexbytes("Key:          ", aes_state.key, 24);
    
    aes_expandkey192(&aes_state);
    
#ifdef PRINT_ROUND_KEYS
    for (i = 1; i <= 12; i++) {
        printf("Round key %2i: ", i);
        print_hexbytes("", aes_state.key + i*16, 16);
    }
#endif
    
    aes_encrypt(&aes_state);
    
    print_hexbytes("Output:       ", aes_state.data, 16);
    
    aes192_decrypt(&aes_state);
    
    print_hexbytes("Decrypted:    ", aes_state.data, 16);   
}

void aes256_test(void) {
    int i;
    struct aes_state aes_state = {
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}
    };
    
    print_hexbytes("Input:        ", aes_state.data, 16);
    print_hexbytes("Key:          ", aes_state.key, 32);
    
    aes_expandkey256(&aes_state);
    
#ifdef PRINT_ROUND_KEYS
    for (i = 1; i <= 14; i++) {
        printf("Round key %2i: ", i);
        print_hexbytes("", aes_state.key + i*16, 16);
    }
#endif
    
    aes_encrypt(&aes_state);
    
    print_hexbytes("Output:       ", aes_state.data, 16);

    aes256_decrypt(&aes_state);
    
    print_hexbytes("Decrypted:    ", aes_state.data, 16);
}

unsigned long aes128_time_test(unsigned int iters) {
    unsigned int i;
    unsigned long tick_count;
    struct aes_state *aes_state, **aes_state_hndl;
    static struct aes_state aes_state_init = {
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
    };
    
    aes_state_hndl = (struct aes_state **)NewHandle(sizeof(struct aes_state),
    		userid(), attrFixed|attrPage|attrBank|attrNoCross, 0x000000);
    if (toolerror())
	return 0;
    aes_state = *aes_state_hndl;
    *aes_state = aes_state_init;

    aes_expandkey128(aes_state);
    
    tick_count = GetTick();
    for (i = 0; i < iters; i++) {
        aes_encrypt(aes_state);
    }
    return GetTick() - tick_count;
}

int main(void) {
    unsigned long tick_count;
    unsigned int test_iters = 1000;
    long double bytes_per_sec;

    printf("AES-128 test:\n");
    aes128_test();
    
    printf("AES-192 test:\n");
    aes192_test();

    printf("AES-256 test:\n");
    aes256_test();
    
    tick_count = aes128_time_test(test_iters);
    printf("%u iterations takes %lu ticks", test_iters, tick_count);
    fflush(stdout);
    bytes_per_sec = (long double)test_iters * 16 * 60 / tick_count;
    printf(" (%lf bytes/sec)\n", bytes_per_sec);
}
