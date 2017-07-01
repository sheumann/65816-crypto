#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sha1.h"

unsigned char buf[0x8000];

int main(int argc, char **argv) {
    struct sha1_context ctx;
    FILE *file;
    size_t count;
    int i;

    srand(time(NULL));

    if (argc != 2)
        return EXIT_FAILURE;

    file = fopen(argv[1], "rb");
    if (file == NULL)
        return EXIT_FAILURE;
    
    sha1_init(&ctx);
    do {
        count = (rand() & 0x7FFF) + 1;
        count = fread(buf, 1, count, file);
        sha1_update(&ctx, buf, count);
    } while (count != 0);
    
    fclose(file);
    sha1_finalize(&ctx);
    
    for (i = 0; i < 20; i++) {
        printf("%02x", ctx.hash[i]);
    }
    printf("\n");
    
    return 0;
}
