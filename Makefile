CC = occ
CFLAGS = -O255 -w255

LIBRARIES = lib65816crypto lib65816hash

PROGRAMS = aescbctest aesctrtest aestest aescrypt sha1sum sha1test \
           sha256sum sha256test md5sum md5test

.PHONY: default
default: $(LIBRARIES) $(PROGRAMS)

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
sha1.B: sha1.a

sha256.a: sha256.cc sha1.h sha256.asm sha1.macros
	$(CC) $(CFLAGS) -c $<
sha256.B: sha256.a

md5.a: md5.cc md5.h md5.asm md5.macros
	$(CC) $(CFLAGS) -c $<
md5.B: md5.a

# Libraries
lib65816crypto: aesmodes.a aes.a
	rm -f $@
	iix makelib -P $@ $(patsubst %,+%,$^)
lib65816hash: sha1.a sha1.B sha256.a sha256.B md5.a md5.B
	rm -f $@
	iix makelib -P $@ $(patsubst %,+%,$^)

# Test programs
aescbctest.a: aescbctest.c aes.h
	$(CC) $(CFLAGS) -c $<
aesctrtest.a: aesctrtest.c aes.h
	$(CC) $(CFLAGS) -c $<
aestest.a: aestest.c aes.h
	$(CC) $(CFLAGS) -c $<
aescrypt.a: aescrypt.c aes.h
	$(CC) $(CFLAGS) -c $<

sha1sum.a: sha1sum.c sha1.h cksumcommon.h
	$(CC) $(CFLAGS) -c $<
sha1test.a: sha1test.c sha1.h
	$(CC) $(CFLAGS) -c $<

sha256sum.a: sha256sum.c sha256.h cksumcommon.h
	$(CC) $(CFLAGS) -c $<
sha256test.a: sha256test.c sha256.h
	$(CC) $(CFLAGS) -c $<

md5sum.a: md5sum.c md5.h cksumcommon.h
	$(CC) $(CFLAGS) -c $<
md5test.a: md5test.c md5.h
	$(CC) $(CFLAGS) -c $<

aescbctest: aescbctest.a pagealign.root lib65816crypto
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816crypto -o $@
aesctrtest: aesctrtest.a pagealign.root lib65816crypto
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816crypto -o $@
aestest: aestest.a pagealign.root lib65816crypto
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816crypto -o $@
aescrypt: aescrypt.a pagealign.root lib65816crypto
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816crypto -o $@

sha1sum: sha1sum.a lib65816hash
	$(CC) $(CFLAGS) $< -L. -llib65816hash -o $@
sha1test: sha1test.a lib65816hash
	$(CC) $(CFLAGS) $< -L. -llib65816hash -o $@

sha256sum: sha256sum.a lib65816hash
	$(CC) $(CFLAGS) $< -L. -llib65816hash -o $@
sha256test: sha256test.a lib65816hash
	$(CC) $(CFLAGS) $< -L. -llib65816hash -o $@

md5sum: md5sum.a pagealign.root lib65816hash
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816hash -o $@
md5test: md5test.a pagealign.root lib65816hash
	$(CC) $(CFLAGS) pagealign.root $< -L. -llib65816hash -o $@


.PHONY: clean
clean:
	rm -f *.a *.A *.b *.B *.root *.ROOT *.o $(PROGRAMS) $(LIBRARIES)
