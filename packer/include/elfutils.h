#ifndef __KITESHIELD_ELFUTILS_H
#define __KITESHIELD_ELFUTILS_H

/* General ELF utility functions */

#include <elf.h>
#include <stddef.h>

#define ELF_FOR_EACH_SYMBOL(elf_start, cursor)                                \
  const Elf64_Shdr *sec = elf_get_sec_by_name(elf_start, ".symtab");          \
  for (Elf64_Sym *cursor = elf_start + sec->sh_offset;                        \
       (void *) cursor < (void *) (elf_start + sec->sh_offset + sec->sh_size);\
       cursor++)                                                              \

const char *elf_get_strtab_str(void *strtab_start, int index);
const char *elf_get_sec_name(void *elf_start, const Elf64_Shdr *shdr);
const Elf64_Shdr *elf_get_sec_by_name(void *elf_start, const char *name);
uint8_t *elf_get_sym(void *elf_start, const Elf64_Sym *sym);
const char *elf_get_sym_name(void *elf_start, const Elf64_Sym *sym,
                             const Elf64_Shdr *strtab);
int elf_sec_contains_sym(const Elf64_Shdr *sec, const Elf64_Sym *sym);

#endif /* __KITESHIELD_ELFUTILS_H */
