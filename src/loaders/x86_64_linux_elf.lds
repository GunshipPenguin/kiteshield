OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
  . = 0x0000000000000000;
  .text : {
    *entry_x86_64_linux_elf.o(.text)
    *loader_x86_64_linux_elf.o(.text)
  }
  .data : {
    *(.data)
  }
}
