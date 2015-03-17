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

	.arch armv6k
	.data
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


@ Subroutines for hook0 are allowed to overwrite only r0, r1 and r2
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
	ldr	r0, .hook0pxiCmd
	str	r0, [r1]
	ldr	pc, hook0ret

.hook1:
	adr	r0, .payloadTop
	adr	r1, .payloadBtm
	ldr	r2, .payloadDst
	mov	r4, r2
	bl	.memcpy64
	bx	r4

.memcpy64:
	sub	r3, r1, r0
	asr	r1, r3, #2
	cmp	r1, #0
	bxle	lr
	lsls	r1, r3, #29
	sub	r0, r0, #4
	sub	r1, r2, #4
	bpl	.memcpy64r1gez
	ldr	r2, [r0, #4]!
	str	r2, [r1, #4]!
.memcpy64r1gez:
	asrs	r2, r3, #3
	bxeq	lr
.memcpy64loop:
	ldr	r3, [r0, #4]
	subs	r2, r2, #1
	str	r3, [r1, #4]
	ldr	r3, [r0, #8]!
	str	r3, [r1, #8]!
	bne	.memcpy64loop
	bx	lr

.payloadTop:
	mvn	r0, #0xE0000007
	mov	r1, #0
	str	r1, [r0]
	ldr	r1, .payloadRegPxiSend
	ldr	r2, .payloadPxiCmd
	str	r2, [r1]
	ldr	r8, .payloadRegShared
	ldr	sl, .payloadArm9Ptr
	ldr	r9, .payloadArm9Payload
	mrs	r0, CPSR
	orr	r0, r0, #0x1C0
	msr	CPSR_xc, r0
.payloadPdnLoop:
	ldrb	r0, [r8]
	ands	r0, r0, #1
	bne	.payloadPdnLoop
	str	r9, [sl]
	mvn	r0, #0xE0000007
.payloadLoop:
	ldr	r1, [r0]
	cmp	r1, #0
	beq	.payloadLoop
	bx	r1

.payloadRegPxiSend:
	.word	0x10163008
.payloadPxiCmd:
	.word	0x44846
.payloadRegShared:
	.word	0x10141000
.payloadArm9Ptr:
	.word	0x2400000C
.payloadArm9Payload:
	.word	0x23F00000
.payloadBtm:

.delay:
	subs	r0, r0, #2
	nop
	bgt	.delay
	bx	lr

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

.hook0pxiCmd:
	.word	0x44836

.payloadDst:
	.word	0x1FFFFC00

	.size	arm11PayloadTop, .-arm11PayloadTop

	.global	arm11PayloadBtm
arm11PayloadBtm:
