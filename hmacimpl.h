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

/*
 * This file is a template for computing HMACs using the hash functions
 * from lib65816hash.  It is #included from the files implementing the
 * hash functions, with HASH_ALG defined to the name of the hash function.
 */

#define join(a,b) a##b
#define concat(a,b) join(a,b)

#define join3(a,b,c) a##b##c
#define concat3(a,b,c) join3(a,b,c)

#define hash_init     concat(HASH_ALG,_init)
#define hash_update   concat(HASH_ALG,_update)
#define hash_finalize concat(HASH_ALG,_finalize)

#define hmac_init     concat3(hmac_,HASH_ALG,_init)
#define hmac_update   concat3(hmac_,HASH_ALG,_update)
#define hmac_finalize concat3(hmac_,HASH_ALG,_finalize)
#define hmac_compute  concat3(hmac_,HASH_ALG,_compute)
#define hmac_context  concat3(hmac_,HASH_ALG,_context)

#define BLOCK_SIZE sizeof(context->u[0].ctx.block)
#define HASH_SIZE  sizeof(context->u[0].ctx.hash)

void hmac_init(struct hmac_context *context,
               const unsigned char *key,
               unsigned long key_length)
{

    unsigned i;

    // Compute adjusted key (hashed from original key if necessary)
    memset(context->u[0].k, 0, BLOCK_SIZE);
    if (key_length <= BLOCK_SIZE) {
        memcpy(context->u[0].k, key, key_length);
    } else {
        hash_init(&context->u[1].ctx);
        hash_update(&context->u[1].ctx, key, key_length);
        hash_finalize(&context->u[1].ctx);
        memcpy(context->u[0].k, context->u[1].ctx.hash, HASH_SIZE);
    }

    // Set context->u[0].k to K XOR opad, context->u[1].k to K XOR ipad
    for (i = 0; i < BLOCK_SIZE; i++) {
        context->u[1].k[i] = context->u[0].k[i] ^ 0x36;
        context->u[0].k[i] ^= 0x5C;
    }
    
    // Save inner hash context following initial block as context->u[2].ctx
    hash_init(&context->u[2].ctx);
    hash_update(&context->u[2].ctx, context->u[1].k, BLOCK_SIZE);
    
    // Save outer hash context following initial block as context->u[1].ctx
    hash_init(&context->u[1].ctx);
    hash_update(&context->u[1].ctx, context->u[0].k, BLOCK_SIZE);

    // initialize context for use with hmac_update
    context->u[0].ctx = context->u[2].ctx;
}


void hmac_update(struct hmac_context *context,
               const unsigned char *message_part,
               unsigned long part_length)
{
    hash_update(&context->u[0].ctx, message_part, part_length);
}


void hmac_finalize(struct hmac_context *context)
{
    // finalize inner hash
    hash_finalize(&context->u[0].ctx);
    memcpy(context->inner_hash, context->u[0].ctx.hash, HASH_SIZE);
    
    // Compute outer hash
    context->u[0].ctx = context->u[1].ctx;
    hash_update(&context->u[0].ctx, context->inner_hash, HASH_SIZE);
    hash_finalize(&context->u[0].ctx);
}


void hmac_compute(struct hmac_context *context,
               const unsigned char *message,
               unsigned long message_length)
{
    // Compute inner hash
    context->u[0].ctx = context->u[2].ctx;
    hash_update(&context->u[0].ctx, message, message_length);
    hash_finalize(&context->u[0].ctx);
    memcpy(context->inner_hash, context->u[0].ctx.hash, HASH_SIZE);
    
    // Compute outer hash
    context->u[0].ctx = context->u[1].ctx;
    hash_update(&context->u[0].ctx, context->inner_hash, HASH_SIZE);
    hash_finalize(&context->u[0].ctx);
}
