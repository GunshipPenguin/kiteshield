OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
  . = 0x0000000000000000;
  .key : {
    *loader.o(.key)
  }
  .text : {
    *entry.o(.text)
    *loader.o(.text)
    *runtime.o(.text)
    *key_utils.o(.text)
  }
  .data : {
    *(.data)
  }
  .tp_info : {
    *runtime.o(.tp_info)
  }
}

