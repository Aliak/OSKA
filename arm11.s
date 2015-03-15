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
	b	hook_FFF84DD4
	b	hook_FFFF097C

hook_FFF84DD4:
	ldr	r0, =0x44836
	str	r0, [r1]
	ldr	pc, =0xFFF84DDC

hook_FFFF097C:
	ldr	r0, =0xFFFF0994
	add	r1, r0, #52
	add	pc, r0, #-16

	.global	arm11PayloadBtm
arm11PayloadBtm:
