65816 Cryptographic & Hash Libraries
====================================

This package contains libraries implementing cryptographic algorithms for the 65816, suitable for use on the Apple IIgs and potentially also other 65816-based systems.  Currently, it includes implementations of AES and RC4 encryption and decryption (in `lib65816crypto`), and of the MD4, MD5, SHA-1, and SHA-256 hash functions (in `lib65816hash`).  The core algorithms for each of these are written in carefully optimized assembly code, and they can generally process at least several thousand bytes per second on a 2.8 MHz Apple IIgs.

Using the Libraries
-------------------
These libraries can easily be used from ORCA/C, or from ORCA/M or other assemblers that permit linking to OMF libraries.  (With appropriate glue code, they could also be used from other languages.)  Refer to the included header files for documentation on how to call them.  Note that each algorithm uses a 'context' structure which must be in bank 0.  This can be allocated on the stack (e.g. by using a local variable in C), although maximum performance will be obtained if it is page-aligned.

If you are calling these algorithms from assembly language, simply follow the usual conventions for calling ORCA/C code: push the arguments on the stack in reverse order, and then JSL to the function.  The data bank must be set to the bank containing the library code (which is in the default, blank-named load segment), and the functions must be called in full native mode.

If you use these libraries in your program, you will need to link them into it.  You can either place the libraries in the `Libraries` directory of your ORCA installation, or place them somewhere else and specify them on the command line when linking your program.  When using certain algorithms (currently AES and MD5), you may also need to include `pagealign.root` as the first file on the linker command line.  This file contains no code, but simply specifies that the default load segment should be page-aligned.  This is needed because those algorithms include data tables that are page-aligned to maximize performance.

Note that some of the algorithms implemented in this package (including RC4, MD4, MD5, and SHA-1) have known security weaknesses.  If you are using any of these algorithms in a situation where security is important, you should refer to up-to-date cryptanalytic results and advice to determine whether they are appropriate for your application.

Building the Libraries
----------------------
If you want to build these libraries yourself, you will need ORCA/M and ORCA/C.  To ensure everything builds correctly, I recommend using [ORCA/C 2.2.0 or later][1].  The included `Makefile` is set up to build the libraries and test programs on a modern system using [Golden Gate][2], but they could also be build under the ORCA shell or GNO with a suitable build script.

[1]: https://github.com/byteworksinc/ORCA-C/releases
[2]: http://golden-gate.ksherlock.com

File Checksum Programs
----------------------
This package also includes versions of the `md5sum`, `sha1sum`, and `sha256sum` programs, which can be run under the ORCA shell or GNO.  These utilities compute file checksums using the corresponding hash algorithms and can be useful for verifying the integrity of files.
