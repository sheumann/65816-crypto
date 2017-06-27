enum aes_keysize {aes_keysize_128=0, aes_keysize_192=64, aes_keysize_256=128};

struct aes_state {
	unsigned char data[16];
	unsigned char reserved[16];
	unsigned char keysize;
	unsigned char key[16*15];
};

/* state must be in bank 0, preferably page-aligned. */
void aes_expandkey128(struct aes_state *state);
void aes_encrypt(struct aes_state *state);
