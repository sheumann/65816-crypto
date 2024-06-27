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
 
/* Simple toy program to encrypt/decrypt files with AES */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

#define BUFFER_SIZE 0x4000

unsigned char inbuf[BUFFER_SIZE];
unsigned char outbuf[BUFFER_SIZE];

unsigned char iv[16] = "abcdefghijklmnop";

int main(int argc, char **argv) {
    FILE *infile, *outfile;
    size_t count;
    char *filename;
    struct aes_context context;
    int encrypt;
    
    if (argc != 4) {
        fprintf(stderr, "wrong number of arguments\n");
        exit(EXIT_FAILURE);
    }
    
    if (strncmp(argv[1], "-d", 2) == 0) {
        encrypt = 0;
    } else if (strncmp(argv[1], "-e", 2) == 0) {
        encrypt = 1;
    }
    
    infile = fopen(argv[3], "rb");
    if (infile == NULL) {
        fprintf(stderr, "error opening input file\n");
        return EXIT_FAILURE;
    }

    filename = malloc(strlen(argv[3]) + 5);
    strcpy(filename, argv[3]);
    if (encrypt) {
        strcat(filename, ".aes");
    } else {
        strcat(filename, ".dec");
    }
    
    outfile = fopen(filename, "wb");
    if (filename == NULL) {
        fprintf(stderr, "error opening output file\n");
        return EXIT_FAILURE;
    }
    
    memcpy(context.data, iv, 16);
    strncpy(context.key, argv[2], 32);
    
    aes128_expandkey(&context);

    do {
        count = fread(inbuf, 1, BUFFER_SIZE, infile);
        count = (count + 15) / 16;
        if (encrypt) {
            aes_cbc_encrypt(&context, inbuf, outbuf, count);
        } else {
            aes_cbc_decrypt(&context, inbuf, outbuf, count, iv);
            if (count != 0)
                memcpy(iv, inbuf + (count - 1) * 16, 16);
        }
        count *= 16;
        if (fwrite(outbuf, 1, count, outfile) != count) {
            fprintf(stderr, "error writing file\n");
            goto finish;
        }
    } while (count != 0);

finish:
    fclose(infile);
    fclose(outfile);
    
    free(filename);
}
