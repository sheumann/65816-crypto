/*
 * Copyright (c) 2017 Stephen Heumann
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sha256.h"

unsigned char buf[0x8000];

int main(int argc, char **argv) {
    struct sha256_context ctx;
    FILE *file;
    size_t count;
    int i;

    srand(time(NULL));

    if (argc != 2)
        return EXIT_FAILURE;

    file = fopen(argv[1], "rb");
    if (file == NULL)
        return EXIT_FAILURE;
    
    sha256_init(&ctx);
    do {
        count = (rand() & 0x7FFF) + 1;
        count = fread(buf, 1, count, file);
        sha256_update(&ctx, buf, count);
    } while (count != 0);
    
    fclose(file);
    sha256_finalize(&ctx);
    
    for (i = 0; i < 32; i++) {
        printf("%02x", ctx.hash[i]);
    }
    printf("\n");
    
    return 0;
}
