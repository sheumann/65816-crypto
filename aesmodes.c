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

#pragma noroot
#pragma lint -1
#pragma optimize -1

#include <string.h>
#include "aes.h"

extern void AES_ENCRYPT(void);
extern void AES_DECRYPT(void);

/*
 * Encrypt data using AES-128, AES-192, or AES-256 in CBC mode.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * The initialization vector (IV) must be in context->data.
 * nblocks gives the number of 16-byte blocks to be processed.
 */
void aes_cbc_encrypt(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks)
{
    

    while (nblocks-- > 0) {
        asm {
            lda [in]
            eor [context]
            sta [context]
            ldy #2
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            
            phd
            lda context
            tcd
            jsl AES_ENCRYPT
            lda 0
            pld
            
            sta [out]
            ldy #2
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
            iny
            iny
            lda [context],y
            sta [out],y
        }
        in += 16;
        out += 16;
    }
}


/*
 * Decrypt data using AES-128, AES-192, or AES-256 in CBC mode.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * nblocks gives the number of 16-byte blocks to be processed.
 */
void aes_cbc_decrypt(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks,
                     const unsigned char *iv)
{
    if (nblocks-- == 0)
        return;

    asm {
        lda [in]
        sta [context]
        ldy #2
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
        iny
        iny
        lda [in],y
        sta [context],y
            
        phd
        lda context
        tcd
        jsl AES_DECRYPT
        pld
    
        ldy #0
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
        iny
        iny
        lda [context],y
        eor [iv],y
        sta [out],y
    }
    in += 16;
    out += 16;

    while (nblocks-- > 0) {
        asm {
            lda [in]
            sta [context]
            ldy #2
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
            iny
            iny
            lda [in],y
            sta [context],y
        
            phd
            lda context
            tcd
            jsl AES_DECRYPT
            pld
        }
        in -= 16;
        asm {
            ldy #0
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
        }
        in += 32;
        out += 16;
    }
}

/*
 * Process data using AES-128, AES-192, or AES-256 in CTR mode.
 * This either encrypts or decrypts data, depending on whether
 * in contains plaintext or ciphertext.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * nblocks gives the number of 16-byte blocks to be processed.
 * counter will be interpreted as a 128-bit big-endian integer,
 * and incremented for each block processed.
 */
void aes_ctr_process(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks,
                     const unsigned char *counter)
{
    while (nblocks-- > 0) {
        asm {
            lda [counter]
            sta [context]
            ldy #2
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            iny
            iny
            lda [counter],y
            sta [context],y
            
            phd
            lda context
            tcd
            jsl AES_ENCRYPT
            pld
        
            lda [context]
            eor [in]
            sta [out]
            ldy #2
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y
            iny
            iny
            lda [context],y
            eor [in],y
            sta [out],y

            ldy #14
incloop:    lda [counter],y
            xba
            inc a
            xba
            sta [counter],y
            bne incdone
            dey
            dey
            bpl incloop
incdone:
        }
        in += 16;
        out += 16;
    }
}

