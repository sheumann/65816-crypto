/*
 * Copyright (c) 2017 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 
/* Implementation of modes of operation for AES */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Memory.h>
#include <MiscTool.h>
#include <orca.h>
#include "aes.h"

/* Example vectors from NIST SP 800-38A */

unsigned char initial_counter[16] = {
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
};

unsigned char counter[16];

unsigned char key128[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};

unsigned char key192[24] = {
    0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
    0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
    0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
};

unsigned char key256[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};

unsigned char plaintext[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
    0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
    0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
};

unsigned char output[64];
unsigned char output2[64];

#define BUFSIZE 64000

static void printhex(char *str, unsigned char *buf, unsigned int count) {
    unsigned int i;

    if (str)
        printf("%s\n", str);

    for (i = 0; i < count; i++) {
        printf("%02x", buf[i]);
        if (i && (i & 0x0F) == 0x0F)
            printf("\n");
    }
}

int main(void) {
    struct aes_context **context_hndl;
    struct aes_context *context;
    unsigned char *inbuf, *outbuf;
    unsigned long tick_count;
    long double bytes_per_sec;

    context_hndl = (struct aes_context **)NewHandle(sizeof(struct aes_context),
                userid(), attrFixed|attrPage|attrBank|attrNoCross, 0x000000);
    if (toolerror())
        return 0;
    context = *context_hndl;
    
    memcpy(context->key, key128, 16);
    aes128_expandkey(context);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, plaintext, output, 4, counter);
    printhex("AES-128 ciphertext:", output, 64);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, output, output2, 4, counter);
    printhex("Decrypted plaintext:", output2, 64);

    
    memcpy(context->key, key192, 24);
    aes192_expandkey(context);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, plaintext, output, 4, counter);
    printhex("AES-192 ciphertext:", output, 64);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, output, output2, 4, counter);
    printhex("Decrypted plaintext:", output2, 64);


    memcpy(context->key, key256, 32);
    aes256_expandkey(context);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, plaintext, output, 4, counter);
    printhex("AES-256 ciphertext:", output, 64);
    
    memcpy(counter, initial_counter, 16);
    aes_ctr_process(context, output, output2, 4, counter);
    printhex("Decrypted plaintext:", output2, 64);
    
    /* Timing tests */
    inbuf = calloc(BUFSIZE, 1);
    outbuf = malloc(BUFSIZE);
    if (inbuf == NULL || outbuf == NULL)
        return -1;
    
    memcpy(context->key, key128, 16);
    aes128_expandkey(context);
    memcpy(counter, initial_counter, 16);
    
    tick_count = GetTick();
    aes_ctr_process(context, inbuf, outbuf, BUFSIZE / 16, counter);
    tick_count = GetTick() - tick_count;
    bytes_per_sec = (long double)BUFSIZE * 60 / tick_count;
    printf("AES-128 CTR encryption/decryption: %lf bytes/sec\n", bytes_per_sec);
}
