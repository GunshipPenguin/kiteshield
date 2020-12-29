OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
  /* Base address the loader code is found at (ie. LOADER_ADDR, see
   * common/include/defs.h) *plus* sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Phdr).
   * (as the first segment will include one ehdr and a phdr for both the loader
   * and packed binary). Note that if this address is changed, LOADER_ADDR must
   * be updated accordingly.
   */
  . = 0x4000b0;
  .key : {
    *loader.o(.key)
  }
  .text : {
    *entry.o(.text)
    *loader.o(.text)
    *runtime.o(.text)
    *key_utils.o(.text)
  }
  .bss : {
    *(.bss)
  }
  .data : {
    *(.data)
  }
  .tp_info : {
    *runtime.o(.tp_info)
  }
}

