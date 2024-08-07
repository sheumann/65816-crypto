/*
 * Copyright (c) 2023 Stephen Heumann
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
#include <orca.h>
#include <memory.h>

#include "sha256.h"
#include "sha1.h"
#include "md5.h"
#include "md4.h"

int main(void) {
    Handle context_hndl;
    struct hmac_sha256_context *hmac_sha256_context;
    struct hmac_sha1_context *hmac_sha1_context;
    struct hmac_md5_context *hmac_md5_context;
    struct hmac_md4_context *hmac_md4_context;
    
    char key[] = "key";
    char msg[] = "The quick brown fox jumps over the lazy dog";

    context_hndl = NewHandle(sizeof(struct hmac_sha256_context),
                userid(), attrFixed|attrPage|attrBank|attrNoCross, 0x000000);
    if (toolerror())
        return 0;


    hmac_sha256_context = (struct hmac_sha256_context *)*context_hndl;
    hmac_sha256_init(hmac_sha256_context, key, sizeof(key)-1);
    hmac_sha256_compute(hmac_sha256_context, msg, sizeof(msg)-1);
    
    printf("HMAC-SHA256: ");
    for (int i = 0; i < sizeof(hmac_sha256_result(hmac_sha256_context)); i++) {
        printf("%02x", hmac_sha256_result(hmac_sha256_context)[i]);
    }
    printf("\n");
        
    hmac_sha1_context = (struct hmac_sha1_context *)*context_hndl;
    hmac_sha1_init(hmac_sha1_context, key, sizeof(key)-1);
    hmac_sha1_compute(hmac_sha1_context, msg, sizeof(msg)-1);
    
    printf("HMAC-SHA1:   ");
    for (int i = 0; i < sizeof(hmac_sha1_result(hmac_sha1_context)); i++) {
        printf("%02x", hmac_sha1_result(hmac_sha1_context)[i]);
    }
    printf("\n");

    hmac_md5_context = (struct hmac_md5_context *)*context_hndl;
    hmac_md5_init(hmac_md5_context, key, sizeof(key)-1);
    hmac_md5_compute(hmac_md5_context, msg, sizeof(msg)-1);
    
    printf("HMAC-MD5:    ");
    for (int i = 0; i < sizeof(hmac_md5_result(hmac_md5_context)); i++) {
        printf("%02x", hmac_md5_result(hmac_md5_context)[i]);
    }
    printf("\n");


    hmac_md4_context = (struct hmac_md4_context *)*context_hndl;
    hmac_md4_init(hmac_md4_context, key, sizeof(key)-1);
    hmac_md4_compute(hmac_md4_context, msg, sizeof(msg)-1);
    
    printf("HMAC-MD4:    ");
    for (int i = 0; i < sizeof(hmac_md4_result(hmac_md4_context)); i++) {
        printf("%02x", hmac_md4_result(hmac_md4_context)[i]);
    }
    printf("\n");

    hmac_sha256_init(hmac_sha256_context, key, sizeof(key)-1);
    hmac_sha256_update(hmac_sha256_context, "T", 1);
    hmac_sha256_update(hmac_sha256_context, msg+1, sizeof(msg)-2);
    hmac_sha256_finalize(hmac_sha256_context);
    
    printf("HMAC-SHA256 (incremental calculation): ");
    for (int i = 0; i < sizeof(hmac_sha256_result(hmac_sha256_context)); i++) {
        printf("%02x", hmac_sha256_result(hmac_sha256_context)[i]);
    }
    printf("\n");

    hmac_sha1_init(hmac_sha1_context, key, sizeof(key)-1);
    hmac_sha1_update(hmac_sha1_context, "T", 1);
    hmac_sha1_update(hmac_sha1_context, msg+1, sizeof(msg)-2);
    hmac_sha1_finalize(hmac_sha1_context);
    
    printf("HMAC-SHA1 (incremental calculation): ");
    for (int i = 0; i < sizeof(hmac_sha1_result(hmac_sha1_context)); i++) {
        printf("%02x", hmac_sha1_result(hmac_sha1_context)[i]);
    }
    printf("\n");

    hmac_md5_init(hmac_md5_context, key, sizeof(key)-1);
    hmac_md5_update(hmac_md5_context, "T", 1);
    hmac_md5_update(hmac_md5_context, msg+1, sizeof(msg)-2);
    hmac_md5_finalize(hmac_md5_context);
    
    printf("HMAC-MD5 (incremental calculation): ");
    for (int i = 0; i < sizeof(hmac_md5_result(hmac_md5_context)); i++) {
        printf("%02x", hmac_md5_result(hmac_md5_context)[i]);
    }
    printf("\n");

    hmac_md4_init(hmac_md4_context, key, sizeof(key)-1);
    hmac_md4_update(hmac_md4_context, "T", 1);
    hmac_md4_update(hmac_md4_context, msg+1, sizeof(msg)-2);
    hmac_md4_finalize(hmac_md4_context);
    
    printf("HMAC-MD4 (incremental calculation): ");
    for (int i = 0; i < sizeof(hmac_md4_result(hmac_md4_context)); i++) {
        printf("%02x", hmac_md4_result(hmac_md4_context)[i]);
    }
    printf("\n");
}
