CFLAGS = -O255 -w255

PROGRAMS = aescbctest aesctrtest aestest aescrypt sha1sum sha1test \
           sha256sum sha256test md5sum md5test

.PHONY: default
default: $(PROGRAMS)

aescbctest: pagealign.asm aescbctest.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) pagealign.asm aescbctest.c aesmodes.c aes.asm -o aescbctest

aesctrtest: pagealign.asm aesctrtest.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) pagealign.asm aesctrtest.c aesmodes.c aes.asm -o aesctrtest

aestest: pagealign.asm aestest.c aes.asm aes.macros aes.h
	occ $(CFLAGS) pagealign.asm aestest.c aes.asm -o aestest

aescrypt: pagealign.asm aescrypt.c aesmodes.c aes.asm aes.macros aes.h
	occ $(CFLAGS) pagealign.asm aescrypt.c aesmodes.c aes.asm -o aescrypt

sha1sum: sha1sum.c sha1.cc sha1.asm sha1.macros sha1.h
	occ $(CFLAGS) sha1sum.c sha1.cc -o sha1sum

sha1test: sha1test.c sha1.cc sha1.asm sha1.macros sha1.h
	occ $(CFLAGS) sha1test.c sha1.cc -o sha1test

sha256sum: sha256sum.c sha256.cc sha256.asm sha256.macros sha256.h
	occ $(CFLAGS) sha256sum.c sha256.cc -o sha256sum

sha256test: sha256test.c sha256.cc sha256.asm sha256.macros sha256.h
	occ $(CFLAGS) sha256test.c sha256.cc -o sha256test

md5sum: pagealign.asm md5sum.c md5.cc md5.asm md5.macros md5.h
	occ $(CFLAGS) pagealign.asm md5sum.c md5.cc -o md5sum

md5test: pagealign.asm md5test.c md5.cc md5.asm md5.macros md5.h
	occ $(CFLAGS) pagealign.asm md5test.c md5.cc -o md5test

.PHONY: clean
clean:
	rm -f *.a *.A *.b *.B *.root *.ROOT *.o $(PROGRAMS)
