struct aes_context {
	unsigned char data[16];
	unsigned char reserved1[17];
	unsigned char key[32];
	unsigned char reserved2[16*13];
};

/* context must be in bank 0, preferably page-aligned. */
void aes128_expandkey(struct aes_context *);
void aes128_expandkey(struct aes_context *);
void aes128_expandkey(struct aes_context *);

void aes_encrypt(struct aes_context *);

void aes128_decrypt(struct aes_context *);
void aes192_decrypt(struct aes_context *);
void aes256_decrypt(struct aes_context *);
