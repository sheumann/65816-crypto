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

struct aes_context {
	unsigned char data[16];
	unsigned char reserved1[17];
	unsigned char key[32];
	unsigned char reserved2[16*13];
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
 * The encrypted input and unencrypted output are in context->data.
 */
void aes128_decrypt(struct aes_context *context);
void aes192_decrypt(struct aes_context *context);
void aes256_decrypt(struct aes_context *context);
