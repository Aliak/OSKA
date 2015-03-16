	.cpu arm946e-s
	.section .text.start
	.align	2

	.global	_start
	.type	_start, %function
_start:
	b	_start
	.size	_start, .-_start
