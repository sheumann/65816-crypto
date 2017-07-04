/*
 * Copyright (c) 2017 Stephen Heumann
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

struct sha256_context {
	unsigned long length;
	unsigned long length2;
	unsigned short extra;
	unsigned char reserved1[50];
	unsigned char hash[32];
	unsigned char block[64];
	unsigned char reserved2[60];
};

/*
 * The context structure must be in bank 0, preferably page-aligned.
 */

/*
 * Initialize a context for SHA-256 computation.
 * An init function must be called before any of the other SHA-256 functions.
 */
void sha256_init(struct sha256_context *context);

/*
 * Initialize a context for SHA-224 computation.
 * To compute a SHA-224 hash, call this function, and then call the below
 * functions as if computing a SHA-256 hash. After calling sha256_finalize,
 * the first 28 bytes of context->hash will contain the SHA-224 hash.
 */
void sha224_init(struct sha256_context *context);

/*
 * Update a SHA-256 context based on the specified data.
 */
void sha256_update(struct sha256_context *context, const unsigned char *data, unsigned long length);

/*
 * Finish SHA-256 processing and generate the final hash code.
 */
void sha256_finalize(struct sha256_context *context);

/*
 * Process one 64-byte block through the SHA-256 hashing function.
 * This is a low-level function; users should normally not call this directly.
 */
void sha256_processblock(struct sha256_context *context);
