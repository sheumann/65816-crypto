/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 * This file is a template for computing a key-derivation function
 * ("KDF in Counter Mode" as specified in NIST SP 800-108), which may
 * use various HMAC functions (among others) as a "pseudo-random function."
 *
 * This file is #included from the files implementing the hash functions,
 * with KDF_PRF defined to the name of the pseudo-random function being used,
 * and KDF_PRF_h defined to the width of its output in bits.
 */

#include <string.h>

#define join(a,b) a##b
#define concat(a,b) join(a,b)

#define KDF_PRF_init     concat(KDF_PRF,_init)
#define KDF_PRF_update   concat(KDF_PRF,_update)
#define KDF_PRF_finalize concat(KDF_PRF,_finalize)
#define KDF_PRF_result   concat(KDF_PRF,_result)
#define KDF_PRF_context  concat(KDF_PRF,_context)

#define KDF_PRF_kdf_ctr  concat(KDF_PRF,_kdf_ctr)

/*
 * This implements "KDF in Counter Mode" as specified in NIST SP 800-108.
 * See that specification for details of its parameters.
 * 
 * This implementation can be instantiated for various pseudo-random functions
 * (e.g. HMACs).  It assumes r = 32, and assumes big-endian byte order is used
 * for integers.  L must be a multiple of 8.  The result buffer must be L bits
 * (i.e. L/8 bytes) long.  The PRF context structure must be provided for use
 * within this function; its state at the beginning and end is not meaningful.
 */
void KDF_PRF_kdf_ctr(struct KDF_PRF_context *ctx,
                     const unsigned char *k_in, unsigned key_len,
                     unsigned long L, unsigned char *result,
                     const char *label, unsigned long label_len,
                     const char *context, unsigned long context_len)
{
    unsigned long n, i;
    static const char zero = 0;
    unsigned long lastSize;

    n = L / KDF_PRF_h;
    lastSize = L % KDF_PRF_h;
    if (lastSize != 0) {
        n++;
    } else {
        lastSize = KDF_PRF_h;
    }

    for (i = 1; i && i <= n; i++) {
        KDF_PRF_init(ctx, k_in, key_len);
        KDF_PRF_update(ctx, (unsigned char *)&i + 3, 1);
        KDF_PRF_update(ctx, (unsigned char *)&i + 2, 1);
        KDF_PRF_update(ctx, (unsigned char *)&i + 1, 1);
        KDF_PRF_update(ctx, (unsigned char *)&i + 0, 1);
        KDF_PRF_update(ctx, label, label_len);
        KDF_PRF_update(ctx, &zero, 1);
        KDF_PRF_update(ctx, context, context_len);
        KDF_PRF_update(ctx, (unsigned char *)&L + 3, 1);
        KDF_PRF_update(ctx, (unsigned char *)&L + 2, 1);
        KDF_PRF_update(ctx, (unsigned char *)&L + 1, 1);
        KDF_PRF_update(ctx, (unsigned char *)&L + 0, 1);
        KDF_PRF_finalize(ctx);
        if (i != n) {
            memcpy(result, KDF_PRF_result(ctx), KDF_PRF_h/8);
            result += KDF_PRF_h/8;
        } else {
            memcpy(result, KDF_PRF_result(ctx), lastSize/8);
        }
    }
}
