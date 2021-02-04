#ifndef __KITESHIELD_ELFUTILS_H
#define __KITESHIELD_ELFUTILS_H

/* General ELF utility functions */

#include <elf.h>
#include <stddef.h>

struct mapped_elf {
  uint8_t *start;
  size_t size;

  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr_tbl;
  Elf64_Shdr *shdr_tbl;

  const Elf64_Shdr *shstrtab;
  const Elf64_Shdr *strtab;
  const Elf64_Shdr *symtab;
  const Elf64_Shdr *text;
};

#define ELF_FOR_EACH_SYMBOL(elf, __cursor)                                                        \
  for (Elf64_Sym *__cursor = (Elf64_Sym *) (elf->start + elf->symtab->sh_offset);                 \
       (void *) __cursor < (void *) (elf->start + elf->symtab->sh_offset + elf->symtab->sh_size); \
       __cursor++)                                                                                \

void parse_mapped_elf(
    void *start,
    size_t size,
    struct mapped_elf *elf);

const char *elf_get_sec_name(
    const struct mapped_elf *elf,
    const Elf64_Shdr *shdr);

const Elf64_Shdr *elf_get_sec_by_name(
    const struct mapped_elf *elf,
    const char *name);

uint8_t *elf_get_sym_location(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym);

const char *elf_get_sym_name(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym);

const Elf64_Sym *elf_get_first_fcn_alias(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym);

int elf_sym_in_text(
    const struct mapped_elf *elf,
    const Elf64_Sym *func);

#endif /* __KITESHIELD_ELFUTILS_H */

