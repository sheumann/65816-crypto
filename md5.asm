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


* Implementation of the MD5 hash function for the 65816

	case	on
	mcopy	md5.macros

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
g_times_4 private
	dc i4' 0,  4,  8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60'
	dc i4' 4, 24, 44,  0, 20, 40, 60, 16, 36, 56, 12, 32, 52,  8, 28, 48'
	dc i4'20, 32, 44, 56,  4, 16, 28, 40, 52,  0, 12, 24, 36, 48, 60,  8'
	dc i4' 0, 28, 56, 20, 48, 12, 40,  4, 32, 60, 24, 52, 16, 44,  8, 36'
	end

k	private
	dc i4'$d76aa478, $e8c7b756, $242070db, $c1bdceee'
	dc i4'$f57c0faf, $4787c62a, $a8304613, $fd469501'
	dc i4'$698098d8, $8b44f7af, $ffff5bb1, $895cd7be'
	dc i4'$6b901122, $fd987193, $a679438e, $49b40821'
	dc i4'$f61e2562, $c040b340, $265e5a51, $e9b6c7aa'
	dc i4'$d62f105d, $02441453, $d8a1e681, $e7d3fbc8'
	dc i4'$21e1cde6, $c33707d6, $f4d50d87, $455a14ed'
	dc i4'$a9e3e905, $fcefa3f8, $676f02d9, $8d2a4c8a'
	dc i4'$fffa3942, $8771f681, $6d9d6122, $fde5380c'
	dc i4'$a4beea44, $4bdecfa9, $f6bb4b60, $bebfbc70'
	dc i4'$289b7ec6, $eaa127fa, $d4ef3085, $04881d05'
	dc i4'$d9d4d039, $e6db99e5, $1fa27cf8, $c4ac5665'
	dc i4'$f4292244, $432aff97, $ab9423a7, $fc93a039'
	dc i4'$655b59c3, $8f0ccc92, $ffeff47d, $85845dd1'
	dc i4'$6fa87e4f, $fe2ce6e0, $a3014314, $4e0811a1'
	dc i4'$f7537e82, $bd3af235, $2ad7d2bb, $eb86d391'
	end

* Initialize a MD5 context.
* This must be called before any of the other MD5 functions.
md5_init start
	CFunction MD5_INIT
	end

MD5_INIT start
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


* Process one 64-byte block through the MD5 hashing function.
* This is a low-level function; users should normally not call this directly.
md5_processblock start
	CFunction MD5_PROCESSBLOCK
	end

MD5_PROCESSBLOCK start
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
	
	rtl
	end
