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

/*
 * This file is a template for computing file checksums with the various
 * different hash functions from lib65816hash.  This should be #included
 * from another file after HASH_FUNCTION is defined to the name of the
 * hash function to use and the corresponding header is included.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define join(a,b) a##b
#define concat(a,b) join(a,b)

unsigned char buf[0x8000ul];

int main(int argc, char **argv) {
    struct concat(HASH_FUNCTION,_context) ctx;
    FILE *file;
    size_t count;
    int i, n;

    srand(time(NULL));

    if (argc < 2) {
        fprintf(stderr, "Usage: %s filename ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (n = 1; n < argc; n++) {
        file = fopen(argv[n], "rb");
        if (file == NULL) {
            perror(argv[n]);
            return EXIT_FAILURE;
        }

        concat(HASH_FUNCTION,_init)(&ctx);
        do {
#ifdef RANDOMIZE_READ_SIZE
            count = (rand() & 0x7FFF) + 1;
#else
            count = 0x8000ul;
#endif
            count = fread(buf, 1, count, file);
            concat(HASH_FUNCTION,_update)(&ctx, buf, count);
        } while (count != 0);

        if (ferror(file)) {
            fprintf(stderr, "Error reading file\n");
        }

        fclose(file);
        concat(HASH_FUNCTION,_finalize)(&ctx);

        for (i = 0; i < sizeof(ctx.hash); i++) {
            printf("%02x", ctx.hash[i]);
        }
        printf("  %s\n", argv[n]);
    }
    
    return 0;
}
