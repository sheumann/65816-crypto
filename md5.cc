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

#include "md5.h"
#include <string.h>

#define length_offset 0
#define extra_offset 8
#define hash_offset 40
#define data_offset 60

extern void MD5_PROCESSBLOCK(void);

/*
 * Update a MD5 context based on the specified data.
 */
void md5_update(struct md5_context *context,
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
                jsl MD5_PROCESSBLOCK
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
            jsl MD5_PROCESSBLOCK
            pld
        }
        length -= 64;
        data += 64;
    }

    memcpy(&context->block, data, length);
    context->extra = length;
}


/*
 * Finish MD5 processing and generate the final hash code.
 */
void md5_finalize(struct md5_context *context)
{
    unsigned int extra = context->extra;

    context->block[extra++] = 0x80;
    
    memset(&context->block[extra], 0, 64 - extra);
    
    if (extra > 64 - 8) {
        asm {
            phd
            lda context
            tcd
            jsl MD5_PROCESSBLOCK
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
        
        lda length_offset
        sta data_offset+56
        lda length_offset+2
        sta data_offset+58
        lda length_offset+4
        sta data_offset+60
        lda length_offset+6
        sta data_offset+62
        
        /* Process final block */
        jsl MD5_PROCESSBLOCK

        pld
    }
}

#define HASH_ALG md5
#include "hmacimpl.h"

#append "md5.asm"
