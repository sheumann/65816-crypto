struct sha1_context {
	unsigned long length;
	unsigned long length2;
	unsigned short extra;
	unsigned char reserved1[30];
	unsigned char hash[20];
	unsigned char chunk[64];
	unsigned char reserved2[16];
};

void sha1_init(struct sha1_context *context);
void sha1_processchunk(struct sha1_context *context);

void sha1_update(struct sha1_context *context, const unsigned char *data, unsigned long length);

void sha1_finalize(struct sha1_context *context);
