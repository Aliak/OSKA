/*
 * Copyright (C) 2015 Aliak <aliakr18@gmail.com>
 * Copyright (C) 2015 173210 <root.3.173210@live.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

@ Subroutines are allowed to overwrite only r0, r1 and r2

	.arch armv6k
	.section .rodata
	.align 2

	.global	arm11PayloadTop
arm11PayloadTop:
	b	.hook0
	b	.hook1

	.global	pdnReg
pdnReg:
	nop

	.global	pxiReg
pxiReg:
	nop

	.global	hook0ret
hook0ret:
	nop

	.global	hook1ret
hook1ret:
	nop

.hook0:
	push	{ r1, r2, lr }

	mov	r0, #0
	bl	.pxiSend
	bl	.pxiSync
	mov	r0, #65536
	bl	.pxiSend
	bl	.pxiRecv
	bl	.pxiRecv
	bl	.pxiRecv

	ldr	r1, pdnReg
	mov	r0, #2
	strb	r0, [r1, #560]
	mov	r0, #16
	bl	.delay
	mov	r0, #0
	strb	r0, [r1, #560]
	mov	r0, #16
	bl	.delay

	pop	{ r1, r2, lr }
	ldr	r0, .hook0_r0
	str	r0, [r1]
	ldr	pc, hook0ret

.hook1:
	ldr	r0, hook1ret
	add	r1, r0, #68
	add	r0, r0, #16
	add	pc, r0, #-16

.delay:
	subs	r0, r0, #2
	nop
	bgt .delay
	bx lr

.pxiSend:
	ldr	r1, pxiReg
.pxiSendLoop:
	ldrh	r2, [r1, #4]
	tst	r2, #2
	bne	.pxiSendLoop
	str	r0, [r1, #8]
	bx	lr

.pxiSync:
	ldr	r0, pxiReg
	ldrb	r1, [r0, #3]
	orr	r1, r1, #64
	strb	r1, [r0, #3]
	bx	lr

.pxiRecv:
	ldr	r0, pxiReg
.pxiRecvLoop:
	ldrh	r1, [r0, #4]
	tst	r1, #256
	bne	.pxiRecvLoop
	ldr	r0, [r0, #12]
	bx	lr

.hook0_r0:
	.word	0x44836

	.size	arm11PayloadTop, .-arm11PayloadTop

	.global	arm11PayloadBtm
arm11PayloadBtm:
