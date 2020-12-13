#include <elf.h>

#include "common/include/defs.h"
#include "common/include/key_utils.h"

#include "loader/include/types.h"

void loader_key_deobfuscate(struct key_info *old_ki, struct key_info *new_ki) {
  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *) LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)
                            (LOADER_ADDR + us_ehdr->e_phoff);

  /* The first ELF segment (loader code) includes the ehdr and two phdrs,
   * adjust loader code start and size accordingly */
  size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  void *loader_start = (void *) loader_phdr->p_vaddr + hdr_adjust;
  size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

  obf_deobf_key(old_ki, new_ki, loader_start, loader_size);
}

