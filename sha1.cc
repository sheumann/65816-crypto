#pragma noroot
#pragma lint -1
#pragma optimize -1

#include "sha1.h"
#include <string.h>

#define length_offset 0
#define extra_offset 8
#define hash_offset 40
#define data_offset 60

extern void SHA1_PROCESSCHUNK(void);

void sha1_update(struct sha1_context *context,
                 const unsigned char *data,
                 unsigned long length)
{
    unsigned int extra = context->extra;

    context->length += length;

    if (extra > 0) {
        if (length >= 64 - extra) {
            memcpy(&context->chunk[extra], data, 64 - extra);
            sha1_processchunk(context);
            length -= 64 - extra;
            data += 64 - extra;
        } else {
            memcpy(&context->chunk[extra], data, length);
            context->extra += length;
            return;
        }
    }
    
    while (length >= 64) {
        memcpy(&context->chunk, data, 64);
        sha1_processchunk(context);
        length -= 64;
        data += 64;
    }

    memcpy(&context->chunk, data, length);
    context->extra = length;
}


void sha1_finalize(struct sha1_context *context)
{
    unsigned int extra = context->extra;

    context->chunk[extra++] = 0x80;
    
    memset(&context->chunk[extra], 0, 64 - extra);
    
    if (extra > 64 - 8) {
        sha1_processchunk(context);
        memset(&context->chunk, 0, 64);
    }
    
    /* Append total length in bits */
    asm {
        phd
        lda context
        tcd
        
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
        
        jsl SHA1_PROCESSCHUNK

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

        pld
    }
}

#append "sha1.asm"
