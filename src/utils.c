#include <elf.h>
#include <string.h>
#include "include/utils.h"

void init_ehdr(Elf64_Ehdr *ehdr, Elf64_Addr entry) {
  /* Ident array */
  ehdr->e_ident[EI_MAG0] = ELFMAG0;
  ehdr->e_ident[EI_MAG1] = ELFMAG1;
  ehdr->e_ident[EI_MAG2] = ELFMAG2;
  ehdr->e_ident[EI_MAG3] = ELFMAG3;
  ehdr->e_ident[EI_CLASS] = ELFCLASS64;
  ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr->e_ident[EI_VERSION] = EV_CURRENT;
  ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr->e_ident[EI_ABIVERSION] = 0;
  memset(ehdr->e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);

  ehdr->e_type = ET_EXEC;
  ehdr->e_machine = EM_X86_64;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_entry = entry;
  ehdr->e_phoff = sizeof(Elf64_Ehdr);
  ehdr->e_shoff = 0;
  ehdr->e_flags = 0;
  ehdr->e_ehsize = sizeof(Elf64_Ehdr);
  ehdr->e_phentsize = sizeof(Elf64_Phdr);
  ehdr->e_phnum = 2;
  ehdr->e_shentsize = sizeof(Elf64_Shdr);
  ehdr->e_shnum = 0;
  ehdr->e_shstrndx = SHN_UNDEF;
}

void init_phdr(Elf64_Phdr *phdr, Elf64_Off offset, Elf64_Addr vaddr, uint64_t size, uint64_t flags, uint64_t align) {
  phdr->p_type = PT_LOAD;
  phdr->p_offset = offset;
  phdr->p_vaddr = vaddr;
  phdr->p_paddr = vaddr;
  phdr->p_filesz = size;
  phdr->p_memsz = size;
  phdr->p_flags = flags;
  phdr->p_align = align;
}
