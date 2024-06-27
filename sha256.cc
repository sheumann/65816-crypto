/*
 * Copyright (c) 2017,2023 Stephen Heumann
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

#include "sha256.h"
#include <string.h>

#define length_offset 0
#define extra_offset 8
#define hash_offset 60
#define data_offset 92

extern void SHA256_PROCESSBLOCK(void);

/*
 * Update a SHA-256 context based on the specified data.
 */
void sha256_update(struct sha256_context *context,
                 const unsigned char *data,
                 unsigned long length)
{
    unsigned int extra = context->extra;
    unsigned long oldlength = context->length;

    if ((context->length += length) < oldlength)
        context->length2++;

    if (extra > 0) {
        if (length >= 64 - extra) {
            memcpy(&context->block[extra], data, 64 - extra);
            asm {
                phd
                lda context
                tcd
                jsl SHA256_PROCESSBLOCK
                pld
            }
            length -= 64 - extra;
            data += 64 - extra;
        } else {
            memcpy(&context->block[extra], data, length);
            context->extra += length;
            return;
        }
    }
    
    while (length >= 64) {
        memcpy(&context->block, data, 64);
        asm {
            phd
            lda context
            tcd
            jsl SHA256_PROCESSBLOCK
            pld
        }
        length -= 64;
        data += 64;
    }

    memcpy(&context->block, data, length);
    context->extra = length;
}


/*
 * Finish SHA-256 processing and generate the final hash code.
 */
void sha256_finalize(struct sha256_context *context)
{
    unsigned int extra = context->extra;

    context->block[extra++] = 0x80;
    
    memset(&context->block[extra], 0, 64 - extra);
    
    if (extra > 64 - 8) {
        asm {
            phd
            lda context
            tcd
            jsl SHA256_PROCESSBLOCK
            pld
        }
        memset(&context->block, 0, 64 - 8);
    }
    
    asm {
        phd
        lda context
        tcd
        
        /* Append total length in bits */
        asl length_offset
        rol length_offset+2
        rol length_offset+4
        rol length_offset+6
        asl length_offset
        rol length_offset+2
        rol length_offset+4
        rol length_offset+6
        asl length_offset
        rol length_offset+2
        rol length_offset+4
        rol length_offset+6
        
        lda length_offset+6
        xba
        sta data_offset+56
        lda length_offset+4
        xba
        sta data_offset+58
        lda length_offset+2
        xba
        sta data_offset+60
        lda length_offset
        xba
        sta data_offset+62
        
        /* Process final block */
        jsl SHA256_PROCESSBLOCK

        /* Flip hash state words to big-endian order */
        lda hash_offset
        xba
        tay
        lda hash_offset+2
        xba
        sta hash_offset
        sty hash_offset+2
        
        lda hash_offset+4
        xba
        tay
        lda hash_offset+4+2
        xba
        sta hash_offset+4
        sty hash_offset+4+2

        lda hash_offset+8
        xba
        tay
        lda hash_offset+8+2
        xba
        sta hash_offset+8
        sty hash_offset+8+2

        lda hash_offset+12
        xba
        tay
        lda hash_offset+12+2
        xba
        sta hash_offset+12
        sty hash_offset+12+2

        lda hash_offset+16
        xba
        tay
        lda hash_offset+16+2
        xba
        sta hash_offset+16
        sty hash_offset+16+2

        lda hash_offset+20
        xba
        tay
        lda hash_offset+20+2
        xba
        sta hash_offset+20
        sty hash_offset+20+2
        
        lda hash_offset+24
        xba
        tay
        lda hash_offset+24+2
        xba
        sta hash_offset+24
        sty hash_offset+24+2
        
        lda hash_offset+28
        xba
        tay
        lda hash_offset+28+2
        xba
        sta hash_offset+28
        sty hash_offset+28+2

        pld
    }
}

#define HASH_ALG sha256
#include "hmacimpl.h"

#define KDF_PRF hmac_sha256
#define KDF_PRF_h 256
#include "kdfimpl.h"

#append "sha256.asm"
