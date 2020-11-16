#include <stdio.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "packer/include/utils.h"
#include "common/include/rc4.h"
#include "common/include/defs.h"
#include "loaders/loader_headers/loader_x86_64.h"

/* Virtual address at which the twice encrypted ELF is to be
 * initially loaded by the kernel (this is the p_vaddr field).
 * The loader will then copy it to another address, peel off
 * the first layer of encryption, and run it. */
#define APP_VADDR 0xA00000ULL

int read_input_elf(char *path, void **buf_ptr, size_t *elf_buf_size) {
  FILE *file;
  CK(file = fopen(path, "r"), NULL)
  CK(fseek(file, 0L, SEEK_END), -1)

  CK(*elf_buf_size = ftell(file), -1)
  CK(*buf_ptr = malloc(*elf_buf_size), NULL)

  CK(fseek(file, 0L, SEEK_SET), -1)
  CK(fread(*buf_ptr, *elf_buf_size, 1, file), 0)

  CK(fclose(file), EOF)

  return 0;
}

int produce_output_elf(FILE *output_file, void *input_elf, size_t input_elf_size) {
  /* ELF header */
  Elf64_Addr entry_vaddr = KITESHIELD_STUB_BASE + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 2;
  Elf64_Ehdr ehdr;
  init_ehdr(&ehdr, entry_vaddr);
  CK(fwrite(&ehdr, sizeof(ehdr), 1, output_file), 0)

  /* Program header for stub */
  Elf64_Phdr stub_phdr;
  init_phdr(&stub_phdr,
      0,
      KITESHIELD_STUB_BASE,
      sizeof(loader_x86_64),
      PF_R | PF_W | PF_X,
      0x200000);
  CK(fwrite(&stub_phdr, sizeof(stub_phdr), 1, output_file), 0)

  /* Program header for packed application */
  Elf64_Off app_offset = ftell(output_file) + sizeof(Elf64_Phdr) + sizeof(loader_x86_64);
  Elf64_Addr app_vaddr = APP_VADDR + app_offset; /* Keep vaddr aligned with offset */
  Elf64_Phdr app_phdr;
  init_phdr(&app_phdr,
      app_offset,
      app_vaddr,
      input_elf_size,
      PF_R,
      0x200000);
  CK(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0)

  /* Stub loader contents */
  CK(fwrite(loader_x86_64, sizeof(loader_x86_64), 1, output_file), 0)

  /* Packed application contents */
  CK(fwrite(input_elf, input_elf_size, 1, output_file), 0)

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: kiteshield <input> <output>\n");
    exit(1);
  }

  void *elf_buf;
  size_t elf_buf_size;
  CK(read_input_elf(argv[1], &elf_buf, &elf_buf_size), -1)

  FILE *output_elf;
  CK(output_elf = fopen(argv[2], "w"), NULL)
  CK(produce_output_elf(output_elf, elf_buf, elf_buf_size), -1)

  CK(fclose(output_elf), EOF)
  CK(chmod(argv[2], S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1)

  return 0;
}
