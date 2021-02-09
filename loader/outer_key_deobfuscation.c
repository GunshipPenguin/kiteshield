#include <elf.h>

#include "common/include/defs.h"
#include "common/include/obfuscation.h"

#include "loader/include/types.h"

/* Convenience wrapper around obf_deobf_outer_key to automatically pass in
 * correct loader code offsets. */
void loader_outer_key_deobfuscate(
    struct rc4_key *old_key,
    struct rc4_key *new_key)
{
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

  obf_deobf_outer_key(old_key, new_key, loader_start, loader_size);
}

