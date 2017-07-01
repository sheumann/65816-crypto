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


* Implementation of the SHA-1 hash function for the 65816
*
* The basic structure of the hash computation is described in FIPS PUB 180-4,
* although this implementation rearranges some things for better performance.

	case	on
	mcopy	sha1.macros

* Direct page locations	
length	gequ	0
extra	gequ	8
idx	gequ	10
a_	gequ	12	; elements of state
b	gequ	16
c	gequ	20
d	gequ	24
e	gequ	28
f_plus_k gequ	32
temp	gequ	36
h0	gequ	40
h1	gequ	44
h2	gequ	48
h3	gequ	52
h4	gequ	56
w	gequ	60


* Initialize a SHA-1 context.
* This must be called before any of the other SHA-1 functions.
sha1_init start
	CFunction SHA1_INIT
	end

SHA1_INIT start
	lda	#$2301
	sta	h0
	lda	#$6745
	sta	h0+2
	
	lda	#$AB89
	sta	h1
	lda	#$EFCD
	sta	h1+2
	
	lda	#$DCFE
	sta	h2
	lda	#$98BA
	sta	h2+2
	
	lda	#$5476
	sta	h3
	lda	#$1032
	sta	h3+2
	
	lda	#$E1F0
	sta	h4
	lda	#$C3D2
	sta	h4+2
	
	stz	length
	stz	length+2
	stz	length+4
	stz	length+6
	stz	extra
	rtl
	end


* Process one 64-byte block through the SHA-1 hashing function.
* This is a low-level function; users should normally not call this directly.
sha1_processblock start
	CFunction SHA1_PROCESSBLOCK
	end

SHA1_PROCESSBLOCK start
	lda	h0
	sta	a_
	lda	h0+2
	sta	a_+2
	
	lda	h1
	sta	b
	lda	h1+2
	sta	b+2
	
	lda	h2
	sta	c
	lda	h2+2
	sta	c+2
	
	lda	h3
	sta	d
	lda	h3+2
	sta	d+2
	
	lda	h4
	sta	e
	lda	h4+2
	sta	e+2

	ComputeSchedule 1
	BlockLoopPart 1
	jsr	ComputeScheduleSub
	BlockLoopPart 2
	jsr	ComputeScheduleSub
	BlockLoopPart 3
	jsr	ComputeScheduleSub
	BlockLoopPart 4

endloop clc
	lda	h0
	adc	a_
	sta	h0
	lda	h0+2
	adc	a_+2
	sta	h0+2
	
	clc
	lda	h1
	adc	b
	sta	h1
	lda	h1+2
	adc	b+2
	sta	h1+2
	
	clc
	lda	h2
	adc	c
	sta	h2
	lda	h2+2
	adc	c+2
	sta	h2+2
	
	clc
	lda	h3
	adc	d
	sta	h3
	lda	h3+2
	adc	d+2
	sta	h3+2
	
	clc
	lda	h4
	adc	e
	sta	h4
	lda	h4+2
	adc	e+2
	sta	h4+2
	
	rtl

ComputeScheduleSub anop
	ComputeSchedule 2
	rts
	end
