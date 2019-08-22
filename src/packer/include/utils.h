#ifndef KITESHIELD_UTILS_H
#define KITESHIELD_UTILS_H

#define CK(stmt, err) \
  if ((stmt) == err) { \
    perror(#stmt); \
    return -1; \
  }

void init_ehdr(Elf64_Ehdr *, Elf64_Addr);
void init_phdr(Elf64_Phdr *, Elf64_Off, Elf64_Addr, uint64_t, uint64_t, uint64_t);

#endif
