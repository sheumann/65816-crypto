CFLAGS = -O255 -w255

PROGRAMS = aescbctest aesctrtest aestest aescrypt sha1sum sha1test sha256sum sha256test

.PHONY: default
default: $(PROGRAMS)

aescbctest: aesalign.asm aescbctest.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) aesalign.asm aescbctest.c aesmodes.c aes.asm -o aescbctest

aesctrtest: aesalign.asm aesctrtest.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) aesalign.asm aesctrtest.c aesmodes.c aes.asm -o aesctrtest

aestest: aesalign.asm aestest.c aes.asm aes.macros aes.h
	occ $(CFLAGS) aesalign.asm aestest.c aes.asm -o aestest

aescrypt: aesalign.asm aescrypt.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) aesalign.asm aescrypt.c aesmodes.c aes.asm -o aescrypt

sha1sum: sha1sum.c sha1.cc sha1.asm sha1.macros sha1.h
	occ $(CFLAGS) sha1sum.c sha1.cc -o sha1sum

sha1test: sha1test.c sha1.cc sha1.asm sha1.macros sha1.h
	occ $(CFLAGS) sha1test.c sha1.cc -o sha1test

sha256sum: sha256sum.c sha256.cc sha256.asm sha256.macros sha256.h
	occ $(CFLAGS) sha256sum.c sha256.cc -o sha256sum

sha256test: sha256test.c sha256.cc sha256.asm sha256.macros sha256.h
	occ $(CFLAGS) sha256test.c sha256.cc -o sha256test

.PHONY: clean
clean:
	rm -f *.a *.A *.b *.B *.root *.ROOT *.o $(PROGRAMS)
