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

#include "md4.h"
#include <stdio.h>
#include <MiscTool.h>
#include <Memory.h>
#include <orca.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int i;
    unsigned long tick_count;
    long double bytes_per_sec;
    
    struct md4_context *context, **context_hndl;
    struct md4_context context_init = {0,0,0, {0}, {0}, {0},
        {0x61,0x62,0x63,0x80,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,
         0x18,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00
        }};

    context_hndl = (struct md4_context **)NewHandle(sizeof(struct md4_context),
                   userid(), attrFixed|attrPage|attrBank|attrNoCross, 0x000000);
    if (toolerror())
        return 0;
    context = *context_hndl;
    *context = context_init;
    
    md4_init(context);
    md4_processblock(context);
    
    printf("h[..] = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", 
           context->hash[0], context->hash[1], context->hash[2], context->hash[3], 
           context->hash[4], context->hash[5], context->hash[6], context->hash[7], 
           context->hash[8], context->hash[9], context->hash[10], context->hash[11], 
           context->hash[12], context->hash[13], context->hash[14], context->hash[15]);

    tick_count = GetTick();
    for (i = 0; i < 1000; i++) {
        md4_processblock(context);
    }
    tick_count = GetTick() - tick_count;
    
    bytes_per_sec = (long double)1000 * 64 * 60 / tick_count;
    printf("Time for 1000 iters = %lu ticks (%lf bytes/sec)\n", tick_count, bytes_per_sec);
    
    tick_count = GetTick();
    md4_init(context);
    md4_update(context, (void*)0x030000, 64000);
    md4_finalize(context);
    tick_count = GetTick() - tick_count;
    bytes_per_sec = (long double)1000 * 64 * 60 / tick_count;
    printf("Append time = %lu ticks (%lf bytes/sec)\n", tick_count, bytes_per_sec);

    if (argc > 1) {
        md4_init(context);
        md4_update(context, argv[1], strlen(argv[1]));
        md4_finalize(context);

        printf("h[..] = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", 
               context->hash[0], context->hash[1], context->hash[2], context->hash[3], 
    	       context->hash[4], context->hash[5], context->hash[6], context->hash[7], 
    	       context->hash[8], context->hash[9], context->hash[10], context->hash[11], 
    	       context->hash[12], context->hash[13], context->hash[14], context->hash[15]);
    }
    
}
