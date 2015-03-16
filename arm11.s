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
	.section .rodata
	.align 2

	.global	arm11PayloadTop
arm11PayloadTop:
	b	.hook0
	b	.hook1

.hook0:
	push	{ r1-r7, lr }
	mov	r0, #0
	bl	.pxiSend
	pop	{ r1-r7, lr }
	ldr	r0, .hook0_r0
	str	r0, [r1]
	ldr	pc, arm11PayloadTop + 0x68

.hook1:
	ldr	r0, arm11PayloadTop + 0x6C
	add	r1, r0, #68
	add	r0, r0, #16
	add	pc, r0, #-16

.pxiSend:
	ldr	r1, .pxiReg
.pxiSendLoop:
	ldrh	r2, [r1, #4]
	tst	r2, #2
	bne	.pxiSendLoop
	str	r0, [r1, #8]
	bx	lr

.hook0_r0:
	.word	0x44836

.pxiReg:
	.word	0xFFFCC48C

	.size	arm11PayloadTop, .-arm11PayloadTop

	.global	arm11PayloadBtm
arm11PayloadBtm:
