/*
 * Copyright (c) 2017,2023 Stephen Heumann
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

struct md4_context {
	unsigned long length;
	unsigned long length2;
	unsigned short extra;
	unsigned char reserved1[30];
	unsigned char hash[16];
	unsigned char reserved2[4];
	unsigned char block[64];
};

struct hmac_md4_context {
	union {
		struct md4_context ctx;
		unsigned char k[64];
	} u[3];
	unsigned char inner_hash[16];
};

/*
 * The context structure must be in bank 0, preferably page-aligned.
 */

/*
 * Initialize a md4 context.
 * This must be called before any of the other md4 functions.
 */
void md4_init(struct md4_context *context);

/*
 * Update a md4 context based on the specified data.
 */
void md4_update(struct md4_context *context, const unsigned char *data, unsigned long length);

/*
 * Finish md4 processing and generate the final hash code.
 */
void md4_finalize(struct md4_context *context);

/*
 * Process one 64-byte block through the md4 hashing function.
 * This is a low-level function; users should normally not call this directly.
 */
void md4_processblock(struct md4_context *context);

/*
 * Initialize a context for HMAC-MD4 computation with a specified key.
 * This must be called before any calls to hmac_md4_compute. After 
 * initialization, the context can be used to compute the HMAC for any
 * number of messages.
 */
void hmac_md4_init(struct hmac_md4_context *context,
                   const unsigned char *key,
                   unsigned long key_length);

/*
 * Compute the HMAC-MD4 of a message, using an already-initialized context.
 * The result will be in context->u[0].ctx.hash.
 */
void hmac_md4_compute(struct hmac_md4_context *context,
                      const unsigned char *message,
                      unsigned long message_length);
