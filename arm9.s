	.cpu arm946e-s
	.section .text.start
	.align	2

	.global	_start
	.type	_start, %function
_start:
	mov	r0, #0x18000000
	add	r1, r0, #0x00600000
	mov	r2, #0xFFFFFFFF
.loop:
	str	r2, [r0], #4
	cmp	r0, r1
	bcc	.loop
	mov	r0, #0x18000000
	b	.loop
	.size	_start, .-_start
