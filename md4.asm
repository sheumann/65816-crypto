* Copyright (c) 2017,2023 Stephen Heumann
*
* Permission to use, copy, modify, and/or distribute this software for any
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


* Implementation of the md4 hash function for the 65816

	case	on
	mcopy	md4.macros

* Direct page locations	
length	gequ	0
extra	gequ	8
idx	gequ	10
a_	gequ	12	; elements of state
b	gequ	16
c	gequ	20
d	gequ	24
zero1	gequ	28
temp	gequ	30
zero2	gequ	34
;unused	gequ	36
h0	gequ	40
h1	gequ	44
h2	gequ	48
h3	gequ	52
;unused	gequ	56
m	gequ	60


* Precomputed values of g*4 for each loop iteration, for indexing the message
;	align	256
g_times_4 private
	dc i2' 0,  4,  8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60'
	dc i2' 0, 16, 32, 48,  4, 20, 36, 52,  8, 24, 40, 56, 12, 28, 44, 60'
	dc i2' 0, 32, 16, 48,  8, 40, 24, 56,  4, 36, 20, 52, 12, 44, 28, 60'
	end

* Initialize a md4 context.
* This must be called before any of the other md4 functions.
md4_init start
	CFunction MD4_INIT
	end

MD4_INIT start
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
	
	stz	length
	stz	length+2
	stz	length+4
	stz	length+6
	stz	extra
	
	stz	zero1
	stz	zero2
	rtl
	end


* Process one 64-byte block through the md4 hashing function.
* This is a low-level function; users should normally not call this directly.
md4_processblock start
	CFunction MD4_PROCESSBLOCK
	end

MD4_PROCESSBLOCK start
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
	
	stz	idx
	BlockLoopPart 1
	BlockLoopPart 2
	BlockLoopPart 3

        clc
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
	
	rtl
	end
