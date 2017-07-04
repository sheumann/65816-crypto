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


* Implementation of the SHA-256 (and SHA-224) hash function for the 65816
*
* The basic structure of the hash computation is described in FIPS PUB 180-4,
* although this implementation rearranges some things for better performance.

	case	on
	mcopy	sha256.macros

* Direct page locations	
length	gequ	0
extra	gequ	8
idx	gequ	10
a_	gequ	12	; elements of state
b	gequ	16
c	gequ	20
d	gequ	24
e	gequ	28
f	gequ	32
g	gequ	36
h	gequ	40
temp1	gequ	44
temp2	gequ	48
ch	gequ	52
maj	gequ	56
h0	gequ	60
h1	gequ	64
h2	gequ	68
h3	gequ	72
h4	gequ	76
h5	gequ	80
h6	gequ	84
h7	gequ	88
w	gequ	92
temp3	gequ	156
temp4	gequ	160
k_ptr	gequ	164
zero	gequ	168
two	gequ	170
four	gequ	172
six	gequ	174
eight	gequ	176
ten	gequ	178
twelve	gequ	180
fourteen gequ	182
sixteen	gequ	184
eighteen gequ	186
twenty	gequ	188
twentytwo gequ	190
twentyfour gequ 192
twentysix gequ	194
twentyeight gequ 196
thirty	gequ	198


k private
	dc i4'$428a2f98, $71374491, $b5c0fbcf, $e9b5dba5'
	dc i4'$3956c25b, $59f111f1, $923f82a4, $ab1c5ed5'
	dc i4'$d807aa98, $12835b01, $243185be, $550c7dc3'
	dc i4'$72be5d74, $80deb1fe, $9bdc06a7, $c19bf174'
	dc i4'$e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc'
	dc i4'$2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da'
	dc i4'$983e5152, $a831c66d, $b00327c8, $bf597fc7'
	dc i4'$c6e00bf3, $d5a79147, $06ca6351, $14292967'
	dc i4'$27b70a85, $2e1b2138, $4d2c6dfc, $53380d13'
	dc i4'$650a7354, $766a0abb, $81c2c92e, $92722c85'
	dc i4'$a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3'
	dc i4'$d192e819, $d6990624, $f40e3585, $106aa070'
	dc i4'$19a4c116, $1e376c08, $2748774c, $34b0bcb5'
	dc i4'$391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3'
	dc i4'$748f82ee, $78a5636f, $84c87814, $8cc70208'
	dc i4'$90befffa, $a4506ceb, $bef9a3f7, $c67178f2'
	end

* Initialize a SHA-256 context.
* This must be called before any of the other SHA-256 functions.
sha256_init start
	CFunction SHA256_INIT
	end

SHA256_INIT start
	lda	#$e667
	sta	h0
	lda	#$6a09
	sta	h0+2
	lda	#$ae85
	sta	h1
	lda	#$bb67
	sta	h1+2
	lda	#$f372
	sta	h2
	lda	#$3c6e
	sta	h2+2
	lda	#$f53a
	sta	h3
	lda	#$a54f
	sta	h3+2
	lda	#$527f
	sta	h4
	lda	#$510e
	sta	h4+2
	lda	#$688c
	sta	h5
	lda	#$9b05
	sta	h5+2
	lda	#$d9ab
	sta	h6
	lda	#$1f83
	sta	h6+2
	lda	#$cd19
	sta	h7
	lda	#$5be0
	sta	h7+2
	
	stz	length
	stz	length+2
	stz	length+4
	stz	length+6
	stz	extra
	
	stz	zero
	lda	#2
	sta	two
	lda	#4
	sta	four
	lda	#6
	sta	six
	lda	#8
	sta	eight
	lda	#10
	sta	ten
	lda	#12
	sta	twelve
	lda	#14
	sta	fourteen
	lda	#16
	sta	sixteen
	lda	#18
	sta	eighteen
	lda	#20
	sta	twenty
	lda	#22
	sta	twentytwo
	lda	#24
	sta	twentyfour
	lda	#26
	sta	twentysix
	lda	#28
	sta	twentyeight
	lda	#30
	sta	thirty
	
	rtl
	end


* Process one 64-byte block through the SHA-256 hashing function.
* This is a low-level function; users should normally not call this directly.
sha256_processblock start
	CFunction SHA256_PROCESSBLOCK
	end

SHA256_PROCESSBLOCK start
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

	lda	h5
	sta	f
	lda	h5+2
	sta	f+2
	
	lda	h6
	sta	g
	lda	h6+2
	sta	g+2
	
	lda	h6
	sta	g
	lda	h6+2
	sta	g+2
	
	lda	h7
	sta	h
	lda	h7+2
	sta	h+2

	lda	#k
	sta	k_ptr
	ComputeSchedule 1
	jsr	BlockLoopSub
	jsr	ScheduleAndBlockLoopSub
	jsr	ScheduleAndBlockLoopSub
	jsr	ScheduleAndBlockLoopSub

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

	clc
	lda	h5
	adc	f
	sta	h5
	lda	h5+2
	adc	f+2
	sta	h5+2

	clc
	lda	h6
	adc	g
	sta	h6
	lda	h6+2
	adc	g+2
	sta	h6+2
	
	clc
	lda	h7
	adc	h
	sta	h7
	lda	h7+2
	adc	h+2
	sta	h7+2	
	rtl

ScheduleAndBlockLoopSub anop
	ComputeSchedule 2
BlockLoopSub anop
	BlockLoopPart 1
	rts
	end
