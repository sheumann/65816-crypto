/*
 * Copyright (c) 2024 Stephen Heumann
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

#include <stdio.h>
#include <string.h>

#include "aes.h"

/* AES-CMAC test vectors from RFC 4493 */

unsigned char K[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};

unsigned char K1[16] = {
    0xfb,0xee,0xd6,0x18,0x35,0x71,0x33,0x66,
    0x7c,0x85,0xe0,0x8f,0x72,0x36,0xa8,0xde
};

unsigned char K2[16] = {
    0xf7,0xdd,0xac,0x30,0x6a,0xe2,0x66,0xcc,
    0xf9,0x0b,0xc1,0x1e,0xe4,0x6d,0x51,0x3b
};

unsigned char ex2[16] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
};

unsigned char ex3[40] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11
};

unsigned char ex4[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
    0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
    0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
};


void print_hexbytes(char *prefix, unsigned char *data, unsigned int n) {
    int i;
    
    printf("%s", prefix);
    for (i = 0; i < n; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(void) {
    struct aes_cmac_context *ctx;

    aes_cmac_init(ctx, K);
 
    if (memcmp(ctx->k1, K1, 16) != 0)
        print_hexbytes("wrong K1: got ", ctx->k1, 16);
    if (memcmp(ctx->k2, K2, 16) != 0)
        print_hexbytes("wrong K2: got ", ctx->k2, 16);

    aes_cmac_compute(ctx, "", 0);
    print_hexbytes("Example 1 AES-CMAC: ", ctx->ctx.data, 16);
    aes_cmac_compute(ctx, ex2, sizeof(ex2));
    print_hexbytes("Example 2 AES-CMAC: ", ctx->ctx.data, 16);
    aes_cmac_compute(ctx, ex3, sizeof(ex3));
    print_hexbytes("Example 3 AES-CMAC: ", ctx->ctx.data, 16);
    aes_cmac_compute(ctx, ex4, sizeof(ex4));
    print_hexbytes("Example 4 AES-CMAC: ", ctx->ctx.data, 16);
}
