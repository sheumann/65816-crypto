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

#pragma noroot
#pragma lint -1
#pragma optimize -1

#include <string.h>
#include <stddef.h>
#include "aes.h"

extern void AES_ENCRYPT(void);

static asm void aes_cmac_subkey_compute_step(struct aes_cmac_context *ctx) {
        tdc
        tay
        phb
        plx
        pla
        pld
        sta 1,s
        phx
        plb

        sep #0x20
        asl 15
        rol 14
        rol 13
        rol 12
        rol 11
        rol 10
        rol 9
        rol 8
        rol 7
        rol 6
        rol 5
        rol 4
        rol 3
        rol 2
        rol 1
        rol 0
        bcc done
        lda 15
        eor #0x87
        sta 15
done:   rep #0x20

        tya
        tcd
        rtl
}


/*
 * Initialize a context for AES-CMAC computation with a specified key.
 * This must be called before any calling aes_cmac_compute.
 */
void aes_cmac_init(struct aes_cmac_context *context,
                   const unsigned char key[16])
{
    memcpy(context->ctx.key, key, 16);
    aes128_expandkey(&context->ctx);

    memset(context->ctx.data, 0, 16);
    aes_encrypt(&context->ctx);

    aes_cmac_subkey_compute_step(context);
    memcpy(context->k1, context->ctx.data, 16);

    aes_cmac_subkey_compute_step(context);
    memcpy(context->k2, context->ctx.data, 16);
}


/*
 * Compute the AES-CMAC of a message as a single operation.
 * The result will be in context->ctx.data.
 * The context can be reused for multiple aes_cmac_compute operations.
 */
void aes_cmac_compute(struct aes_cmac_context *context,
                      const unsigned char *message,
                      unsigned long message_length)
{
    unsigned i;

    memset(&context->ctx.data, 0, 16);

    while (message_length > 16) {
        asm {
            lda [message]
            eor [context]
            sta [context]
            ldy #2
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            iny
            iny
            lda [message],y
            eor [context],y
            sta [context],y
            
            phd
            lda context
            tcd
            jsl AES_ENCRYPT
            pld
        }
        
        message_length -= 16;
        message += 16;
    }
    
    if (message_length == 16) {
        for (i = 0; i < 16; i++) {
            context->ctx.data[i] ^= message[i] ^ context->k1[i];
        }
    } else {
        for (i = 0; i < 16; i++) {
            if (i < message_length) {
                context->ctx.data[i] ^= message[i] ^ context->k2[i];
            } else if (i == message_length) {
                context->ctx.data[i] ^= 0x80 ^ context->k2[i];
            } else {
                context->ctx.data[i] ^= context->k2[i];
            }
        }
    }

    asm {
        phd
        lda context
        tcd
        jsl AES_ENCRYPT
        pld
    }
}

