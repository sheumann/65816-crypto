	case	on
	mcopy	sha1.macros
	mcopy	rotate.macros

* Direct page locations	
;chunk	gequ	0	; 8 bytes
a_	gequ	8	; elements of state
b	gequ	12
c	gequ	16
d	gequ	20
e	gequ	24
unused	gequ	28	; result of function in hash computation
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

	ldy	#0
loop	phy
	cpy	#60
	bge	f_60
	cpy	#40
	bge	f_40
	cpy	#20
	bge	f_20

* f_0 to f_19
f_0	lda	c
	eor	d
	and	b
	eor	d
	clc
	adc	#$7999
	sta	f_plus_k
	
	lda	c+2
	eor	d+2
	and	b+2
	eor	d+2
	adc	#$5A82
	sta	f_plus_k+2
	bra	after_f

* f_20 to f_39
f_20	lda	b
	eor	c
	eor	d
	clc
	adc	#$EBA1
	sta	f_plus_k
	
	lda	b+2
	eor	c+2
	eor	d+2
	adc	#$6ED9
	sta	f_plus_k+2
	bra	after_f

* f_40 to f_59
f_40	lda	c
	ora	d
	and	b
	sta	temp
	lda	c
	and	d
	ora	temp
	clc
	adc	#$BCDC
	sta	f_plus_k
	
	lda	c+2
	ora	d+2
	and	b+2
	sta	temp
	lda	c+2
	and	d+2
	ora	temp
	adc	#$8F1B
	sta	f_plus_k+2
	bra	after_f

* f_60 to f_79
f_60	lda	b
	eor	c
	eor	d
	clc
	adc	#$C1D6
	sta	f_plus_k
	
	lda	b+2
	eor	c+2
	eor	d+2
	adc	#$CA62
	sta	f_plus_k+2
	bra	after_f

after_f	anop
	ROTL4MOVE temp,a_,5
	lda	1,s
	asl	a
	asl	a
	tax
	clc
	lda	w,x
	adc	temp
	tay
	lda	w+2,x
	adc	temp+2
	tax
	clc
	tya
	adc	e
	tay
	txa
	adc	e+2
	tax
	clc
	tya
	adc	f_plus_k
	sta	temp
	txa
	adc	f_plus_k+2
	sta	temp+2

	lda	d
	sta	e
	lda	d+2
	sta	e+2

	lda	c
	sta	d
	lda	c+2
	sta	d+2

	ROTL4MOVE c,b,30
	
	lda	a_
	sta	b
	lda	a_+2
	sta	b+2
	
	lda	temp
	sta	a_
	lda	temp+2
	sta	a_+2

	ply
	iny
	cpy	#80
	bge	endloop
	jmp	loop

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
