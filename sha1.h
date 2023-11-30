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

struct sha1_context {
	unsigned long length;
	unsigned long length2;
	unsigned short extra;
	unsigned char reserved1[30];
	unsigned char hash[20];
	unsigned char block[64];
	unsigned char reserved2[16];
};

struct hmac_sha1_context {
	union {
		struct sha1_context ctx;
		unsigned char k[64];
	} u[3];
	unsigned char inner_hash[20];
};

/*
 * The context structure must be in bank 0, preferably page-aligned.
 */

/*
 * Initialize a SHA-1 context.
 * This must be called before any of the other SHA-1 functions.
 */
void sha1_init(struct sha1_context *context);

/*
 * Update a SHA-1 context based on the specified data.
 */
void sha1_update(struct sha1_context *context, const unsigned char *data, unsigned long length);

/*
 * Finish SHA-1 processing and generate the final hash code.
 */
void sha1_finalize(struct sha1_context *context);

/*
 * Process one 64-byte block through the SHA-1 hashing function.
 * This is a low-level function; users should normally not call this directly.
 */
void sha1_processblock(struct sha1_context *context);

/*
 * Initialize a context for HMAC-SHA1 computation with a specified key.
 * This must be called before any calls to hmac_sha1_compute. After 
 * initialization, the context can be used to compute the HMAC for any
 * number of messages.
 */
void hmac_sha1_init(struct hmac_sha1_context *context,
                    const unsigned char *key,
                    unsigned long key_length);

/*
 * Compute the HMAC-SHA1 of a message, using an already-initialized context.
 * The result will be in context->u[0].ctx.hash.
 */
void hmac_sha1_compute(struct hmac_sha1_context *context,
                       const unsigned char *message,
                       unsigned long message_length);
