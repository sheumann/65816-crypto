/*
 * Copyright (c) 2023 Stephen Heumann
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

#include <stdio.h>
#include <string.h>
#include "rc4.h"

int main(int argc, char *argv[]) {
    struct rc4_context context;
    size_t length;
    size_t i;

    if (argc < 3)
        return 0;

    rc4_init(&context, argv[1], strlen(argv[1]));
    
    length = strlen(argv[2]);
    
    rc4_process(&context, argv[2], argv[2], length);
    
    for(i = 0; i < length; i++) {
        printf("%02x", argv[2][i]);
    }
    printf("\n");
}
