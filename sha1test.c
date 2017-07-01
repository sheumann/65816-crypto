#include "sha1.h"
#include <stdio.h>
#include <MiscTool.h>
#include <Memory.h>
#include <orca.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int i;
    unsigned long tick_count;
    long double bytes_per_sec;
    
    struct sha1_context *context, **context_hndl;
    struct sha1_context context_init = {0,0,0, {0}, {0},
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
    
    printf("h[..] = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", 
           context->hash[3], context->hash[2], context->hash[1], context->hash[0], 
	   context->hash[7], context->hash[6], context->hash[5], context->hash[4], 
	   context->hash[11], context->hash[10], context->hash[9], context->hash[8], 
	   context->hash[15], context->hash[14], context->hash[13], context->hash[12], 
	   context->hash[19], context->hash[18], context->hash[17], context->hash[16]);

    tick_count = GetTick();
    for (i = 0; i < 1000; i++) {
        sha1_processchunk(context);
    }
    tick_count = GetTick() - tick_count;
    
    bytes_per_sec = (long double)1000 * 64 * 60 / tick_count;
    printf("Time for 1000 iters = %lu ticks (%lf bytes/sec)\n", tick_count, bytes_per_sec);

    tick_count = GetTick();
    sha1_init(context);
    sha1_update(context, (void*)0x030000, 64000);
    sha1_finalize(context);
    tick_count = GetTick() - tick_count;
    bytes_per_sec = (long double)1000 * 64 * 60 / tick_count;
    printf("Append time = %lu ticks (%lf bytes/sec)\n", tick_count, bytes_per_sec);

    if (argc > 1) {
        sha1_init(context);
        sha1_update(context, argv[1], strlen(argv[1]));
        sha1_finalize(context);

        printf("h[..] = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", 
               context->hash[0], context->hash[1], context->hash[2], context->hash[3], 
    	       context->hash[4], context->hash[5], context->hash[6], context->hash[7], 
    	       context->hash[8], context->hash[9], context->hash[10], context->hash[11], 
    	       context->hash[12], context->hash[13], context->hash[14], context->hash[15], 
    	       context->hash[16], context->hash[17], context->hash[18], context->hash[19]);
    }
}
