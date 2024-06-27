/*
 * Copyright (c) 2017,2024 Stephen Heumann
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

struct aes_context {
	unsigned char data[16];
	unsigned char reserved1[17];
	unsigned char key[32];
	unsigned char reserved2[16*13];
};

struct aes_cmac_context {
	union {
		struct aes_context ctx;
		struct {
			unsigned char padding[16+17+32+16*9];
			unsigned char k1[16];
			unsigned char k2[16];
		};
	};
};

/*
 * The context structure must be in bank 0, preferably page-aligned.
 * Note that a 256-byte (one page) context structure is sufficient for
 * AES-128 and AES-192. The full length is needed only for AES-256.
 */

/*
 * AES key expansion functions
 * The appropriate one of these must be called before encrypting or decrypting.
 * The key must be in the first 16/24/32 bytes of context->key before the call.
 */
void aes128_expandkey(struct aes_context *context);
void aes192_expandkey(struct aes_context *context);
void aes256_expandkey(struct aes_context *context);

/*
 * AES encryption function
 * This performs AES-128, AES-192, or AES-256 encryption, depending on the key.
 * The unencrypted input and encrypted output are in context->data.
 */
void aes_encrypt(struct aes_context *context);

/*
 * AES decryption functions
 * aes_decrypt does AES-128, AES-192, or AES-256 decryption, based on the key.
 * The others use a specific key size; a corresponding key must have been used.
 * The encrypted input and unencrypted output are in context->data.
 */
void aes_decrypt(struct aes_context *context);
void aes128_decrypt(struct aes_context *context);
void aes192_decrypt(struct aes_context *context);
void aes256_decrypt(struct aes_context *context);

/*
 * Encrypt data using AES-128, AES-192, or AES-256 in CBC mode.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * The initialization vector (IV) must be in context->data.
 * nblocks gives the number of 16-byte blocks to be processed.
 */
void aes_cbc_encrypt(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks);

/*
 * Decrypt data using AES-128, AES-192, or AES-256 in CBC mode.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * nblocks gives the number of 16-byte blocks to be processed.
 */
void aes_cbc_decrypt(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks,
                     const unsigned char *iv);

/*
 * Process data using AES-128, AES-192, or AES-256 in CTR mode.
 * This either encrypts or decrypts data, depending on whether
 * in contains plaintext or ciphertext.
 * The key must have been specified via aes{128,192,256}_expandkey().
 * nblocks gives the number of 16-byte blocks to be processed.
 * counter will be interpreted as a 128-bit big-endian integer,
 * and incremented for each block processed.
 */
void aes_ctr_process(struct aes_context *context,
                     const unsigned char *in,
                     unsigned char *out,
                     unsigned long nblocks,
                     const unsigned char *counter);

/*
 * Initialize a context for AES-CMAC computation with a specified key.
 * This must be called before any calling aes_cmac_compute.
 */
void aes_cmac_init(struct aes_cmac_context *context,
                   const unsigned char key[16]);

/*
 * Compute the AES-CMAC of a message as a single operation.
 * The result will be in context->ctx.data.
 * The context can be reused for multiple aes_cmac_compute operations.
 */
void aes_cmac_compute(struct aes_cmac_context *context,
                      const unsigned char *message,
                      unsigned long message_length);

