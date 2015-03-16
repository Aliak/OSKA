	.cpu arm946e-s
	.section .text.start
	.align	2

	.global	_start
	.type	_start, %function
_start:
	ldr	r1, =0x18600000
	mov	r2, #0xFFFFFFFF
.clearScr:
	mov	r0, #0x18000000
.loop:
	str	r2, [r0], #4
	cmp	r0, r1
	bcc	.loop
	b	.clearScr
	.size	_start, .-_start
