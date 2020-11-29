#include <string.h>

#include "packer/include/elfutils.h"

const char *elf_get_sec_name(void *elf_start, const Elf64_Shdr *shdr) {
  Elf64_Ehdr *ehdr = elf_start;
  Elf64_Shdr *shstrtab =
    ((Elf64_Shdr *) (elf_start + ehdr->e_shoff)) + ehdr->e_shstrndx;

  return (const char *) (elf_start + shstrtab->sh_offset + shdr->sh_name);
}

const Elf64_Shdr *elf_get_sec_by_name(void *elf_start, const char *name) {
  Elf64_Ehdr *ehdr = elf_start;
  Elf64_Shdr *curr_shdr = elf_start + ehdr->e_shoff;

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (curr_shdr->sh_type != SHT_NULL &&
        strcmp(elf_get_sec_name(elf_start, curr_shdr), name) == 0)
      return curr_shdr;

    curr_shdr++;
  }

  return NULL;
}

uint8_t *elf_get_sym(void *elf_start, const Elf64_Sym *sym) {
  Elf64_Ehdr *ehdr = elf_start;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (curr_phdr->p_vaddr <= sym->st_value &&
        (curr_phdr->p_vaddr + curr_phdr->p_memsz) < sym->st_value) {
      return (void *) (curr_phdr->p_offset +
                      (curr_phdr->p_vaddr - sym->st_value));
    }
    curr_phdr++;
  }

  return NULL;
}

const char *elf_get_sym_name(void *elf_start, const Elf64_Sym *sym,
                             const Elf64_Shdr *strtab) {
  return (const char *) (elf_start + strtab->sh_offset + sym->st_name);
}

