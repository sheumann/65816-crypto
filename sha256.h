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

struct sha256_context {
	unsigned long length;
	unsigned long length2;
	unsigned short extra;
	unsigned char reserved1[50];
	unsigned char hash[32];
	unsigned char block[64];
	unsigned char reserved2[60];
};

struct hmac_sha256_context {
	union {
		struct sha256_context ctx;
		unsigned char k[64];
	} u[3];
	unsigned char inner_hash[32];
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

/*
 * Initialize a context for HMAC-SHA256 computation with a specified key.
 * This must be called before any other HMAC calls. After initialization,
 * the context can be used with either hmac_sha256_update/hmac_sha256_finalize
 * or hmac_sha256_compute, but they should not be mixed.
 */
void hmac_sha256_init(struct hmac_sha256_context *context,
                      const unsigned char *key,
                      unsigned long key_length);

/*
 * Update an HMAC-SHA256 context based on the specified data.
 */
void hmac_sha256_update(struct hmac_sha256_context *context,
                        const unsigned char *message_part,
                        unsigned long part_length);

/*
 * Finish HMAC-SHA256 processing and generate the final HMAC.
 */
void hmac_sha256_finalize(struct hmac_sha256_context *context);

/*
 * Compute the HMAC-SHA256 of a message as a single operation.
 * The context can be reused for multiple hmac_sha256_compute operations.
 */
void hmac_sha256_compute(struct hmac_sha256_context *context,
                         const unsigned char *message,
                         unsigned long message_length);

/*
 * Get the result of an HMAC-SHA256 computation following hmac_sha256_finalize
 * or hmac_sha256_compute.
 */
#define hmac_sha256_result(context) ((context)->u[0].ctx.hash)

/*
 * This implements "KDF in Counter Mode" as specified in NIST SP 800-108, with
 * HMAC-SHA256 as the pseudo-random function.  See that specification for
 * details of its parameters.
 * 
 * This implementation assumes r = 32 and assumes big-endian byte order is used
 * for integers.  L must be a multiple of 8.  The result buffer must be L bits
 * (i.e. L/8 bytes) long.  The HMAC-SHA256 context must be provided for use
 * within this function; its state at the beginning and end is not meaningful.
 */
void hmac_sha256_kdf_ctr(struct hmac_sha256_context *ctx,
                         const unsigned char *k_in, unsigned key_len,
                         unsigned long L, unsigned char *result,
                         const char *label, unsigned long label_len,
                         const char *context, unsigned long context_len);
