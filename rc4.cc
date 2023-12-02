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

#include "rc4.h"

/*
 * Initialize an RC4 context context with a specified key.
 * This must be called before calling rc4_process.
 */
void rc4_init(struct rc4_context *context,
              const unsigned char *key,
              unsigned keylength)
{
    unsigned int i;
    unsigned char j;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        context->S[i] = i;
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        j = j + context->S[i] + key[i % keylength];
        temp = context->S[j];
        context->S[j] = context->S[i];
        context->S[i] = temp;
    }

    context->i = 0;
    context->j = 0;
}


/*
 * Process data using RC4.  This either encrypts or decrypts data,
 * depending on whether in contains plaintext or ciphertext.
 *
 * To get the raw RC4 output stream, specify the input as all zeros.
 * The same buffer may be used for in and out.
 */
void rc4_process(struct rc4_context *context,
                 const unsigned char *in,
                 unsigned char *out,
                 unsigned long length)
{
    extern unsigned char RC4_PRGA(void);

    while (length--) {
        asm {
            phd
            lda context
            tcd
            
            sep #0x30
            jsl RC4_PRGA
            pld
            
            eor [in]
            sta [out]
            rep #0x30
        }
        in++;
        out++;
    }
}

#append "rc4.asm"
