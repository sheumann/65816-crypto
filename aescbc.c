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
            ldy #0
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
            iny
            iny
            lda [in],y
            eor [context],y
            sta [context],y
            
            phd
            lda context
            tcd
            jsl AES_ENCRYPT
            pld
        }
        memcpy(out, context->data, 16);
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

    memcpy(context->data, in, 16);
    asm {
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
    //in += 16;
    out += 16;

    while (nblocks-- > 0) {
        memcpy(context->data, in+16, 16);
        asm {
            phd
            lda context
            tcd
            jsl AES_DECRYPT
            pld
        
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
        in += 16;
        out += 16;
    }
}
