* Copyright (c) 2023 Stephen Heumann
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

* Direct page locations	
i	gequ	0
j	gequ	1
S	gequ	2

* Do one step of the RC4 pseudo-random generation algorithm.
* Call with DP = RC4 context structure, and short M/X.
RC4_PRGA start
;i := (i + 1) mod 256
	inc	i

;j := (j + S[i]) mod 256
	ldx	i
	clc
	lda	S,x
	tay
	adc	j
	sta	j

;swap values of S[i] and S[j]
	tax
	lda	S,x

	ldx	i
	sta	S,x
	
	ldx	j
	tya
	sta	S,x

;temp := (S[i] + S[j]) mod 256
	ldx	i
	clc
	adc	S,x

;return S[temp]
	tax
	lda	S,x

	rtl
	end
