#include "sha1.h"
#include <stdio.h>
#include <MiscTool.h>
#include <Memory.h>
#include <orca.h>

int main(void) {
    unsigned int i;
    unsigned long tick_count;
    long double bytes_per_sec;
    
    struct sha1_context *context, **context_hndl;
    struct sha1_context context_init = {{0}, 0,0,0,0,0, {0}, 0,0,0,0,0,
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
         0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x18
        },
        {0}};

    context_hndl = (struct sha1_context **)NewHandle(sizeof(struct sha1_context),
                   userid(), attrFixed|attrPage|attrBank|attrNoCross, 0x000000);
    if (toolerror())
        return 0;
    context = *context_hndl;
    *context = context_init;
    
    sha1_init(context);
    sha1_processchunk(context);
    
    printf("abcde = %08lx %08lx %08lx %08lx %08lx\n", context->a, context->b, context->c, context->d, context->e);
    printf("h[..] = %08lx %08lx %08lx %08lx %08lx\n", context->h0, context->h1, context->h2, context->h3, context->h4);

    tick_count = GetTick();
    for (i = 0; i < 1000; i++) {
        sha1_processchunk(context);
    }
    tick_count = GetTick() - tick_count;
    
    bytes_per_sec = (long double)1000 * 64 * 60 / tick_count;
    printf("Time for 1000 iters = %lu ticks (%lf bytes/sec)\n", tick_count, bytes_per_sec);
}
