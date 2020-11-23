OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
  . = 0x0000000000000000;
  .key_info : {
    *loader.o(.key_info)
  }
  .text : {
    *entry.o(.text)
    *loader.o(.text)
    *key_utils.o(.text)
  }
  .data : {
    *(.data)
  }
}

