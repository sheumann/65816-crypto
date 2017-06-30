	case	on
	mcopy	sha1.macros

* Direct page locations	
;chunk	gequ	0	; 8 bytes
a_	gequ	8	; elements of state
b	gequ	12
c	gequ	16
d	gequ	20
e	gequ	24
idx	gequ	28
f40temp	gequ	30
f_plus_k gequ	32
temp	gequ	36
h0	gequ	40
h1	gequ	44
h2	gequ	48
h3	gequ	52
h4	gequ	56
w	gequ	60

initial_value privdata
	dc h'67452301 efcdab89 98badcfe 10325476 c3d2e1f0'
	end


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
	rtl
	end


sha1_processchunk start
	CFunction SHA1_PROCESSCHUNK
	end

SHA1_PROCESSCHUNK start

	ComputeSchedule
	
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

	ldx	#0
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
	
	clc
	lda	h4
	adc	e
	sta	h4
	lda	h4+2
	adc	e+2
	sta	h4+2
	
	rtl
	end
