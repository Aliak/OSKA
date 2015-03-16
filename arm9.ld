OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)

SECTIONS
{
  . = 0x23F00000;
  .text.start : { *(.text.start ) }
  .text       : { *(.text) }
  .rodata     : { *(.rodata) }
  .data       : { *(.data) }
  .bss        : { *(.bss) }
  . = ALIGN(4);
}
