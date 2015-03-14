	.arch armv6k
	.section .rodata
	.align 2

	.global	arm11PayloadTop
arm11PayloadTop:
	b	hook_FFF84DD4
	b	hook_FFFF097C

hook_FFF84DD4:
	ldr	r0, =0x44836
	str	r0, [r1]
	ldr	pc, =0xFFF84DDC

hook_FFFF097C:
	ldr	pc, =0xFFFF0984

	.global	arm11PayloadBtm
arm11PayloadBtm:
