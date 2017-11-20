* Copyright (c) 2017 Stephen Heumann
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


* AES encryption and decryption functions for the 65816
*
* The general approach is largely based on the public domain
* 'aestable.c' implementation by Karl Malbrain, available at:
* https://code.google.com/archive/p/byte-oriented-aes/downloads
* Portions are also based on the public domain 'rijndael-alg-fst.c'
* reference implementation by Vincent Rijmen, Antoon Bosselaers,
* and Paulo Barreto.


	case	on
	mcopy	aes.macros

* Dummy segment to go in .ROOT file
	align	256
dummy	private
	end

* Data tables used for AES encryption and decryption.
* For best performance, these should be page-aligned.
	align	256
tables	privdata
Sbox	anop		; forward s-box
	dc h'63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76'
	dc h'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0'
	dc h'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15'
	dc h'04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75'
	dc h'09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84'
	dc h'53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf'
	dc h'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8'
	dc h'51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2'
	dc h'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73'
	dc h'60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db'
	dc h'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79'
	dc h'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08'
	dc h'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a'
	dc h'70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e'
	dc h'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df'
	dc h'8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'

InvSbox	anop		; inverse s-box
	dc h'52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb'
	dc h'7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb'
	dc h'54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e'
	dc h'08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25'
	dc h'72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92'
	dc h'6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84'
	dc h'90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06'
	dc h'd0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b'
	dc h'3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73'
	dc h'96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e'
	dc h'47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b'
	dc h'fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4'
	dc h'1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f'
	dc h'60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef'
	dc h'a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61'
	dc h'17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d'

Xtime2Sbox anop		; combined Xtimes2[Sbox[]]
	dc h'c6 f8 ee f6 ff d6 de 91 60 02 ce 56 e7 b5 4d ec'
	dc h'8f 1f 89 fa ef b2 8e fb 41 b3 5f 45 23 53 e4 9b'
	dc h'75 e1 3d 4c 6c 7e f5 83 68 51 d1 f9 e2 ab 62 2a'
	dc h'08 95 46 9d 30 37 0a 2f 0e 24 1b df cd 4e 7f ea'
	dc h'12 1d 58 34 36 dc b4 5b a4 76 b7 7d 52 dd 5e 13'
	dc h'a6 b9 00 c1 40 e3 79 b6 d4 8d 67 72 94 98 b0 85'
	dc h'bb c5 4f ed 86 9a 66 11 8a e9 04 fe a0 78 25 4b'
	dc h'a2 5d 80 05 3f 21 70 f1 63 77 af 42 20 e5 fd bf'
	dc h'81 18 26 c3 be 35 88 2e 93 55 fc 7a c8 ba 32 e6'
	dc h'c0 19 9e a3 44 54 3b 0b 8c c7 6b 28 a7 bc 16 ad'
	dc h'db 64 74 14 92 0c 48 b8 9f bd 43 c4 39 31 d3 f2'
	dc h'd5 8b 6e da 01 b1 9c 49 d8 ac f3 cf ca f4 47 10'
	dc h'6f f0 4a 5c 38 57 73 97 cb a1 e8 3e 96 61 0d 0f'
	dc h'e0 7c 71 cc 90 06 f7 1c c2 6a ae 69 17 99 3a 27'
	dc h'd9 eb 2b 22 d2 a9 07 33 2d 3c 15 c9 87 aa 50 a5'
	dc h'03 59 09 1a 65 d7 84 d0 82 29 5a 1e 7b a8 6d 2c'

Xtime3Sbox anop		; combined Xtimes3[Sbox[]]
	dc h'a5 84 99 8d 0d bd b1 54 50 03 a9 7d 19 62 e6 9a'
	dc h'45 9d 40 87 15 eb c9 0b ec 67 fd ea bf f7 96 5b'
	dc h'c2 1c ae 6a 5a 41 02 4f 5c f4 34 08 93 73 53 3f'
	dc h'0c 52 65 5e 28 a1 0f b5 09 36 9b 3d 26 69 cd 9f'
	dc h'1b 9e 74 2e 2d b2 ee fb f6 4d 61 ce 7b 3e 71 97'
	dc h'f5 68 00 2c 60 1f c8 ed be 46 d9 4b de d4 e8 4a'
	dc h'6b 2a e5 16 c5 d7 55 94 cf 10 06 81 f0 44 ba e3'
	dc h'f3 fe c0 8a ad bc 48 04 df c1 75 63 30 1a 0e 6d'
	dc h'4c 14 35 2f e1 a2 cc 39 57 f2 82 47 ac e7 2b 95'
	dc h'a0 98 d1 7f 66 7e ab 83 ca 29 d3 3c 79 e2 1d 76'
	dc h'3b 56 4e 1e db 0a 6c e4 5d 6e ef a6 a8 a4 37 8b'
	dc h'32 43 59 b7 8c 64 d2 e0 b4 fa 07 25 af 8e e9 18'
	dc h'd5 88 6f 72 24 f1 c7 51 23 7c 9c 21 dd dc 86 85'
	dc h'90 42 c4 aa d8 05 01 12 a3 5f f9 d0 91 58 27 b9'
	dc h'38 13 b3 33 bb 70 89 a7 b6 22 92 20 49 ff 78 7a'
	dc h'8f f8 80 17 da 31 c6 b8 c3 b0 77 11 cb fc d6 3a'

;Xtime2	anop
;	dc h'00 02 04 06 08 0a 0c 0e 10 12 14 16 18 1a 1c 1e'
;	dc h'20 22 24 26 28 2a 2c 2e 30 32 34 36 38 3a 3c 3e'
;	dc h'40 42 44 46 48 4a 4c 4e 50 52 54 56 58 5a 5c 5e'
;	dc h'60 62 64 66 68 6a 6c 6e 70 72 74 76 78 7a 7c 7e'
;	dc h'80 82 84 86 88 8a 8c 8e 90 92 94 96 98 9a 9c 9e'
;	dc h'a0 a2 a4 a6 a8 aa ac ae b0 b2 b4 b6 b8 ba bc be'
;	dc h'c0 c2 c4 c6 c8 ca cc ce d0 d2 d4 d6 d8 da dc de'
;	dc h'e0 e2 e4 e6 e8 ea ec ee f0 f2 f4 f6 f8 fa fc fe'
;	dc h'1b 19 1f 1d 13 11 17 15 0b 09 0f 0d 03 01 07 05'
;	dc h'3b 39 3f 3d 33 31 37 35 2b 29 2f 2d 23 21 27 25'
;	dc h'5b 59 5f 5d 53 51 57 55 4b 49 4f 4d 43 41 47 45'
;	dc h'7b 79 7f 7d 73 71 77 75 6b 69 6f 6d 63 61 67 65'
;	dc h'9b 99 9f 9d 93 91 97 95 8b 89 8f 8d 83 81 87 85'
;	dc h'bb b9 bf bd b3 b1 b7 b5 ab a9 af ad a3 a1 a7 a5'
;	dc h'db d9 df dd d3 d1 d7 d5 cb c9 cf cd c3 c1 c7 c5'
;	dc h'fb f9 ff fd f3 f1 f7 f5 eb e9 ef ed e3 e1 e7 e5'

Xtime9	anop
	dc h'00 09 12 1b 24 2d 36 3f 48 41 5a 53 6c 65 7e 77'
	dc h'90 99 82 8b b4 bd a6 af d8 d1 ca c3 fc f5 ee e7'
	dc h'3b 32 29 20 1f 16 0d 04 73 7a 61 68 57 5e 45 4c'
	dc h'ab a2 b9 b0 8f 86 9d 94 e3 ea f1 f8 c7 ce d5 dc'
	dc h'76 7f 64 6d 52 5b 40 49 3e 37 2c 25 1a 13 08 01'
	dc h'e6 ef f4 fd c2 cb d0 d9 ae a7 bc b5 8a 83 98 91'
	dc h'4d 44 5f 56 69 60 7b 72 05 0c 17 1e 21 28 33 3a'
	dc h'dd d4 cf c6 f9 f0 eb e2 95 9c 87 8e b1 b8 a3 aa'
	dc h'ec e5 fe f7 c8 c1 da d3 a4 ad b6 bf 80 89 92 9b'
	dc h'7c 75 6e 67 58 51 4a 43 34 3d 26 2f 10 19 02 0b'
	dc h'd7 de c5 cc f3 fa e1 e8 9f 96 8d 84 bb b2 a9 a0'
	dc h'47 4e 55 5c 63 6a 71 78 0f 06 1d 14 2b 22 39 30'
	dc h'9a 93 88 81 be b7 ac a5 d2 db c0 c9 f6 ff e4 ed'
	dc h'0a 03 18 11 2e 27 3c 35 42 4b 50 59 66 6f 74 7d'
	dc h'a1 a8 b3 ba 85 8c 97 9e e9 e0 fb f2 cd c4 df d6'
	dc h'31 38 23 2a 15 1c 07 0e 79 70 6b 62 5d 54 4f 46'

XtimeB	anop
	dc h'00 0b 16 1d 2c 27 3a 31 58 53 4e 45 74 7f 62 69'
	dc h'b0 bb a6 ad 9c 97 8a 81 e8 e3 fe f5 c4 cf d2 d9'
	dc h'7b 70 6d 66 57 5c 41 4a 23 28 35 3e 0f 04 19 12'
	dc h'cb c0 dd d6 e7 ec f1 fa 93 98 85 8e bf b4 a9 a2'
	dc h'f6 fd e0 eb da d1 cc c7 ae a5 b8 b3 82 89 94 9f'
	dc h'46 4d 50 5b 6a 61 7c 77 1e 15 08 03 32 39 24 2f'
	dc h'8d 86 9b 90 a1 aa b7 bc d5 de c3 c8 f9 f2 ef e4'
	dc h'3d 36 2b 20 11 1a 07 0c 65 6e 73 78 49 42 5f 54'
	dc h'f7 fc e1 ea db d0 cd c6 af a4 b9 b2 83 88 95 9e'
	dc h'47 4c 51 5a 6b 60 7d 76 1f 14 09 02 33 38 25 2e'
	dc h'8c 87 9a 91 a0 ab b6 bd d4 df c2 c9 f8 f3 ee e5'
	dc h'3c 37 2a 21 10 1b 06 0d 64 6f 72 79 48 43 5e 55'
	dc h'01 0a 17 1c 2d 26 3b 30 59 52 4f 44 75 7e 63 68'
	dc h'b1 ba a7 ac 9d 96 8b 80 e9 e2 ff f4 c5 ce d3 d8'
	dc h'7a 71 6c 67 56 5d 40 4b 22 29 34 3f 0e 05 18 13'
	dc h'ca c1 dc d7 e6 ed f0 fb 92 99 84 8f be b5 a8 a3' 

XtimeD	anop
	dc h'00 0d 1a 17 34 39 2e 23 68 65 72 7f 5c 51 46 4b'
	dc h'd0 dd ca c7 e4 e9 fe f3 b8 b5 a2 af 8c 81 96 9b'
	dc h'bb b6 a1 ac 8f 82 95 98 d3 de c9 c4 e7 ea fd f0'
	dc h'6b 66 71 7c 5f 52 45 48 03 0e 19 14 37 3a 2d 20'
	dc h'6d 60 77 7a 59 54 43 4e 05 08 1f 12 31 3c 2b 26'
	dc h'bd b0 a7 aa 89 84 93 9e d5 d8 cf c2 e1 ec fb f6'
	dc h'd6 db cc c1 e2 ef f8 f5 be b3 a4 a9 8a 87 90 9d'
	dc h'06 0b 1c 11 32 3f 28 25 6e 63 74 79 5a 57 40 4d'
	dc h'da d7 c0 cd ee e3 f4 f9 b2 bf a8 a5 86 8b 9c 91'
	dc h'0a 07 10 1d 3e 33 24 29 62 6f 78 75 56 5b 4c 41'
	dc h'61 6c 7b 76 55 58 4f 42 09 04 13 1e 3d 30 27 2a'
	dc h'b1 bc ab a6 85 88 9f 92 d9 d4 c3 ce ed e0 f7 fa'
	dc h'b7 ba ad a0 83 8e 99 94 df d2 c5 c8 eb e6 f1 fc'
	dc h'67 6a 7d 70 53 5e 49 44 0f 02 15 18 3b 36 21 2c'
	dc h'0c 01 16 1b 38 35 22 2f 64 69 7e 73 50 5d 4a 47'
	dc h'dc d1 c6 cb e8 e5 f2 ff b4 b9 ae a3 80 8d 9a 97' 

XtimeE	anop
	dc h'00 0e 1c 12 38 36 24 2a 70 7e 6c 62 48 46 54 5a'
	dc h'e0 ee fc f2 d8 d6 c4 ca 90 9e 8c 82 a8 a6 b4 ba'
	dc h'db d5 c7 c9 e3 ed ff f1 ab a5 b7 b9 93 9d 8f 81'
	dc h'3b 35 27 29 03 0d 1f 11 4b 45 57 59 73 7d 6f 61'
	dc h'ad a3 b1 bf 95 9b 89 87 dd d3 c1 cf e5 eb f9 f7'
	dc h'4d 43 51 5f 75 7b 69 67 3d 33 21 2f 05 0b 19 17'
	dc h'76 78 6a 64 4e 40 52 5c 06 08 1a 14 3e 30 22 2c'
	dc h'96 98 8a 84 ae a0 b2 bc e6 e8 fa f4 de d0 c2 cc'
	dc h'41 4f 5d 53 79 77 65 6b 31 3f 2d 23 09 07 15 1b'
	dc h'a1 af bd b3 99 97 85 8b d1 df cd c3 e9 e7 f5 fb'
	dc h'9a 94 86 88 a2 ac be b0 ea e4 f6 f8 d2 dc ce c0'
	dc h'7a 74 66 68 42 4c 5e 50 0a 04 16 18 32 3c 2e 20'
	dc h'ec e2 f0 fe d4 da c8 c6 9c 92 80 8e a4 aa b8 b6'
	dc h'0c 02 10 1e 34 3a 28 26 7c 72 60 6e 44 4a 58 56'
	dc h'37 39 2b 25 0f 01 13 1d 47 49 5b 55 7f 71 63 6d'
	dc h'd7 d9 cb c5 ef e1 f3 fd a7 a9 bb b5 9f 91 83 8d'

Rcon	anop
	dc h'01 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'02 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00'
	dc h'04 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'08 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'10 00 04 00 00 00 00 00 00 08 00 00 00 00 00 00'
	dc h'20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'40 10 08 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'80 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00'
	dc h'1b 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'36 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'6c 00 20 00 00 00 00 00 00 80 00 00 00 00 00 00'
	dc h'd8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
	dc h'ab 1b 40'
	end

* Direct page locations
state1	gequ	0
state2	gequ	16
keysize	gequ	32
rk	gequ	33

* Constants used for keysize
keysize_128 gequ 0
keysize_192 gequ 64
keysize_256 gequ 128


* AES key expansion functions
* The appropriate one of these must be called before encrypting or decrypting.
* The key should be in the first 16/24/32 bytes of rk before calling this.

* Callable from C, with context structure pointer on stack.
aes128_expandkey start
	CFunction AES128_EXPANDKEY
	end

aes192_expandkey start
	CFunction AES192_EXPANDKEY
	end

aes256_expandkey start
	CFunction AES256_EXPANDKEY
	end

* Call with DP = AES context structure (with key present but not expanded),
*           DB = bank containing AES tables.
AES128_EXPANDKEY start
	using	tables

	stz	keysize-1		;keysize_128
	
	ldx	#16
	clc

top	anop
	ExpandKeyCore 16,0
	ExpandKeyIter 16,3

	txa
	adc	#16
	tax
	cmp	#16*11
	blt	top
	rtl
	end


AES192_EXPANDKEY start
	using	tables

	lda	#keysize_192|8
	sta	keysize-1

	ldx	#24
	clc

top	anop
	ExpandKeyCore 24,1
	ExpandKeyIter 24,5

	txa
	adc	#24
	tax
	cmp	#16*13
	blt	top
	rtl
	end


AES256_EXPANDKEY start
	using	tables
	
	lda	#keysize_256|8
	sta	keysize-1

	ldx	#32
	clc

top	anop
	ExpandKeyCore 32,2
	ExpandKeyIter 32,3

	txa
	adc	#16
	tax
	cmp	#16*15
	bge	done

	ExpandKeySubst 32,2
	ExpandKeyIter 32,3

	txa
	adc	#16
	tax
	brl	top

done	rtl
	end


* AES encryption function
* This performs AES-128, AES-192, or AES-256 encryption, depending on the key.
* The unencrypted input and encrypted output are in state1.

* Callable from C, with context structure pointer on stack.
aes_encrypt start
	CFunction AES_ENCRYPT
	end


* Call with DP = AES context structure (with key expanded),
*           DP = bank containing AES tables.
AES_ENCRYPT start
	using	tables

	AddInitialRoundKey

	ShortRegs

	NormalRound 1
	NormalRound 2
	NormalRound 3
	NormalRound 4
	NormalRound 5
	NormalRound 6
	NormalRound 7
	NormalRound 8
	NormalRound 9
	
	lda	keysize
	bne	cont1
	jmp	finish_aes128

cont1	NormalRound 10
	NormalRound 11

	lda	keysize
	bmi	cont2
	jmp	finish_aes192
	
cont2	NormalRound 12
	NormalRound 13

finish_aes256 anop
	FinalRound 14
	LongRegs
	rtl

finish_aes192 anop
	FinalRound 12
	LongRegs
	rtl

finish_aes128 anop
	FinalRound 10
	LongRegs
	rtl
	end


* AES decryption functions
* The encrypted input and unencrypted output are in state1.

* Callable from C, with context structure pointer on stack.
aes_decrypt start
	CFunction AES_DECRYPT
	end

aes128_decrypt start
	CFunction AES128_DECRYPT
	end

aes192_decrypt start
	CFunction AES192_DECRYPT
	end

aes256_decrypt start
	CFunction AES256_DECRYPT
	end

* Call with DP = AES context structure (with key expanded),
*           DP = bank containing AES tables.
AES_DECRYPT start
	using	tables
	ShortRegs
	lda	keysize
	bne	not128
	jmp	aes128_decrypt_internal
not128	bmi	aes256_decrypt_internal
	jmp	aes192_decrypt_internal

AES256_DECRYPT entry
	ShortRegs
aes256_decrypt_internal anop
	InvFinalRound 14
	InvNormalRound 13
	InvNormalRound 12
	jmp	cont1

AES192_DECRYPT entry
	ShortRegs
aes192_decrypt_internal anop
	InvFinalRound 12
cont1	anop
	InvNormalRound 11
	InvNormalRound 10
	jmp	cont2
	
AES128_DECRYPT entry
	ShortRegs
aes128_decrypt_internal anop
	InvFinalRound 10
cont2	anop
	InvNormalRound 9
	InvNormalRound 8
	InvNormalRound 7
	InvNormalRound 6
	InvNormalRound 5
	InvNormalRound 4
	InvNormalRound 3
	InvNormalRound 2
	InvNormalRound 1
	LongRegs
	rtl
	end
