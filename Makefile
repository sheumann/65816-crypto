CC = occ
CFLAGS = -O255 -w255

PROGRAMS = aescbctest aesctrtest aestest aescrypt sha1sum sha1test \
           sha256sum sha256test md5sum md5test

.PHONY: default
default: $(PROGRAMS)

pagealign.root: pagealign.asm
	$(CC) -c $<
	mv pagealign.ROOT pagealign.root

# AES encryption/decryption algorithm
aesmodes.a: aesmodes.c aes.h
	$(CC) $(CFLAGS) -c $<
aes.a: aes.asm aes.macros
	$(CC) $(CFLAGS) -c $<
	mv aes.A aes.a

# Hash algorithms
sha1.a: sha1.cc sha1.h sha1.asm sha1.macros
	$(CC) $(CFLAGS) -c $<
sha256.a: sha256.cc sha1.h sha256.asm sha1.macros
	$(CC) $(CFLAGS) -c $<
md5.a: md5.cc md5.h md5.asm md5.macros
	$(CC) $(CFLAGS) -c $<

# Test programs
aescbctest.a: aescbctest.c aes.h
	$(CC) $(CFLAGS) -c $<
aesctrtest.a: aesctrtest.c aes.h
	$(CC) $(CFLAGS) -c $<
aestest.a: aestest.c aes.h
	$(CC) $(CFLAGS) -c $<
aescrypt.a: aescrypt.c aes.h
	$(CC) $(CFLAGS) -c $<

sha1sum.a: sha1sum.c sha1.h
	$(CC) $(CFLAGS) -c $<
sha1test.a: sha1test.c sha1.h
	$(CC) $(CFLAGS) -c $<

sha256sum.a: sha256sum.c sha256.h
	$(CC) $(CFLAGS) -c $<
sha256test.a: sha256test.c sha256.h
	$(CC) $(CFLAGS) -c $<

md5sum.a: md5sum.c md5.h
	$(CC) $(CFLAGS) -c $<
md5test.a: md5test.c md5.h
	$(CC) $(CFLAGS) -c $<

aescbctest: pagealign.root aescbctest.a aesmodes.a aes.a
	$(CC) $(CFLAGS) $^ -o $@
aesctrtest: pagealign.root aesctrtest.a aesmodes.a aes.a
	$(CC) $(CFLAGS) $^ -o $@
aestest: pagealign.root aestest.a aes.a
	$(CC) $(CFLAGS) $^ -o $@
aescrypt: pagealign.root aescrypt.a aesmodes.a aes.a
	$(CC) $(CFLAGS) $^ -o $@

sha1sum: sha1sum.a sha1.a
	$(CC) $(CFLAGS) $^ -o $@
sha1test: sha1test.a sha1.a
	$(CC) $(CFLAGS) $^ -o $@

sha256sum: sha256sum.a sha256.a
	$(CC) $(CFLAGS) $^ -o $@
sha256test: sha256test.a sha256.a
	$(CC) $(CFLAGS) $^ -o $@

md5sum: pagealign.root md5sum.a md5.a
	$(CC) $(CFLAGS) $^ -o $@
md5test: pagealign.root md5test.a md5.a
	$(CC) $(CFLAGS) $^ -o $@


.PHONY: clean
clean:
	rm -f *.a *.A *.b *.B *.root *.ROOT *.o $(PROGRAMS)
