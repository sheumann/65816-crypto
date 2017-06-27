struct aes_state {
	unsigned char data[16];
	unsigned char reserved1[17];
	unsigned char key[32];
	unsigned char reserved2[16*13];
};

/* state must be in bank 0, preferably page-aligned. */
void aes_expandkey128(struct aes_state *state);
void aes_expandkey192(struct aes_state *state);
void aes_expandkey256(struct aes_state *state);

void aes_encrypt(struct aes_state *state);

void aes128_decrypt(struct aes_state *state);
void aes192_decrypt(struct aes_state *state);
