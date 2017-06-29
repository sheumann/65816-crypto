struct sha1_context {
	unsigned char reserved1[8];
	unsigned long a,b,c,d,e;
	unsigned char reserved2[12];
	unsigned long h0,h1,h2,h3,h4;
	unsigned char chunk[64];
	unsigned char reserved3[300];
};

int sha1_init(struct sha1_context *context);
int sha1_processchunk(struct sha1_context *context);
