#include <string.h>

#include "packer/include/elfutils.h"

void parse_mapped_elf(
    void *start,
    size_t size,
    struct mapped_elf *elf)
{
  elf->start = start;
  elf->size = size;

  elf->ehdr = (Elf64_Ehdr *) start;
  elf->phdr_tbl = (Elf64_Phdr *) (elf->start + elf->ehdr->e_phoff);
  elf->shdr_tbl = (Elf64_Shdr *) (elf->start + elf->ehdr->e_shoff);

  /* elf_get_sec_by_name only depends on shstrtab being set */
  if (elf->ehdr->e_shstrndx == 0)
    elf->shstrtab = NULL;
  else
    elf->shstrtab = elf->shdr_tbl + elf->ehdr->e_shstrndx;

  elf->strtab = elf_get_sec_by_name(elf, ".strtab");
  elf->symtab = elf_get_sec_by_name(elf, ".symtab");
  elf->text = elf_get_sec_by_name(elf, ".text");
}

const Elf64_Shdr *elf_get_sec_by_name(
    const struct mapped_elf *elf,
    const char *name)
{
  Elf64_Shdr *curr_shdr = elf->shdr_tbl;

  for (int i = 0; i < elf->ehdr->e_shnum; i++) {
    if (curr_shdr->sh_type != SHT_NULL &&
        strcmp(elf_get_sec_name(elf, curr_shdr), name) == 0)
      return curr_shdr;

    curr_shdr++;
  }

  return NULL;
}

const char *elf_get_sec_name(
    const struct mapped_elf *elf,
    const Elf64_Shdr *shdr)
{
  if (elf->shstrtab == NULL)
    return NULL;

  return (const char *) (elf->start + elf->shstrtab->sh_offset + shdr->sh_name);
}

uint8_t *elf_get_sym_location(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym)
{
  for (int i = 0; i < elf->ehdr->e_phnum; i++) {
    Elf64_Phdr *curr_phdr = elf->phdr_tbl + i;

    if (curr_phdr->p_type != PT_LOAD)
      continue;

    if (curr_phdr->p_vaddr <= sym->st_value &&
        (curr_phdr->p_vaddr + curr_phdr->p_memsz) > sym->st_value) {
      return (void *) (elf->start + (curr_phdr->p_offset +
                      (sym->st_value - curr_phdr->p_vaddr)));
    }
  }

  return NULL;
}

int elf_sym_in_text(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym)
{
  return elf->text->sh_addr <= sym->st_value &&
         (elf->text->sh_addr + elf->text->sh_size) > sym->st_value;
}

const char *elf_get_sym_name(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym)
{
  return (const char *) (elf->start + elf->strtab->sh_offset + sym->st_name);
}

const Elf64_Sym *elf_get_first_fcn_alias(
    const struct mapped_elf *elf,
    const Elf64_Sym *sym)
{
  ELF_FOR_EACH_SYMBOL(elf, cursor) {
    if (ELF64_ST_TYPE(cursor->st_info) == STT_FUNC &&
        sym->st_value == cursor->st_value &&
        sym != cursor) {
      return cursor;
    }
  }

  return NULL;
}

