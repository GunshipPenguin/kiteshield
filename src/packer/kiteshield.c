#include <stdio.h>
#include <time.h>
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <stdbool.h>
#include <unistd.h>

#include "bddisasm.h"

#include "packer/include/elfutils.h"
#include "common/include/rc4.h"
#include "common/include/key_utils.h"
#include "common/include/defs.h"
#include "loaders/loader_headers/loader_x86_64.h"

/* Virtual address at which the twice encrypted ELF is to be
 * initially loaded by the kernel (this is the p_vaddr field).
 * The loader will then copy it to another address, peel off
 * the first layer of encryption, and run it. */
#define APP_VADDR 0xA00000ULL

#define CK_NEQ_PERROR(stmt, err)                                              \
  do {                                                                        \
    if ((stmt) == err) {                                                      \
      perror(#stmt);                                                          \
      return -1;                                                              \
    }                                                                         \
  } while(0)

static int log_verbose = 0;

/* Needs to be defined for bddisasm */
int nd_vsnprintf_s(char *buffer, size_t sizeOfBuffer, size_t count,
                   const char *format, va_list argptr) {
  return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}

/* Needs to be defined for bddisasm */
void* nd_memset(void *s, int c, size_t n)  {
  return memset(s, c, n);
}

static void verbose(char *fmt, ...) {
  if (!log_verbose)
    return;

  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);
}

static int read_input_elf(char *path, void **buf_ptr, size_t *elf_buf_size) {
  FILE *file;
  CK_NEQ_PERROR(file = fopen(path, "r"), NULL);
  CK_NEQ_PERROR(fseek(file, 0L, SEEK_END), -1);

  CK_NEQ_PERROR(*elf_buf_size = ftell(file), -1);
  CK_NEQ_PERROR(*buf_ptr = malloc(*elf_buf_size), NULL);

  CK_NEQ_PERROR(fseek(file, 0L, SEEK_SET), -1);
  CK_NEQ_PERROR(fread(*buf_ptr, *elf_buf_size, 1, file), 0);

  CK_NEQ_PERROR(fclose(file), EOF);

  return 0;
}

static int produce_output_elf(FILE *output_file, void *input_elf,
                              size_t input_elf_size) {
  /* The entry address is located right after the struct key_info (used for
   * passing decryption key and other info to loader), which is the first
   * sizeof(struct key_info) bytes of the loader code (guaranteed by the linker
   * script) */
  Elf64_Addr entry_vaddr = KITESHIELD_STUB_BASE +
                           sizeof(Elf64_Ehdr) +
                           (sizeof(Elf64_Phdr) * 2) +
                           sizeof(struct key_info);
  Elf64_Ehdr ehdr;
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;
  memset(ehdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);

  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_entry = entry_vaddr;
  ehdr.e_phoff = sizeof(Elf64_Ehdr);
  ehdr.e_shoff = 0;
  ehdr.e_flags = 0;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = 2;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = 0;
  ehdr.e_shstrndx = SHN_UNDEF;

  CK_NEQ_PERROR(fwrite(&ehdr, sizeof(ehdr), 1, output_file), 0);

  /* Program header for stub */
  Elf64_Phdr stub_phdr;
  stub_phdr.p_type = PT_LOAD;
  stub_phdr.p_offset = 0;
  stub_phdr.p_vaddr = KITESHIELD_STUB_BASE;
  stub_phdr.p_paddr = stub_phdr.p_vaddr;
  stub_phdr.p_filesz = sizeof(loader_x86_64);
  stub_phdr.p_memsz = sizeof(loader_x86_64);
  stub_phdr.p_flags = PF_R | PF_X;
  stub_phdr.p_align = 0x200000;
  CK_NEQ_PERROR(fwrite(&stub_phdr, sizeof(stub_phdr), 1, output_file), 0);

  /* Program header for packed application */
  int app_offset = ftell(output_file) + sizeof(Elf64_Phdr) + sizeof(loader_x86_64);
  Elf64_Phdr app_phdr;
  app_phdr.p_type = PT_LOAD;
  app_phdr.p_offset = app_offset;
  app_phdr.p_vaddr = APP_VADDR + app_offset; /* Keep vaddr aligned */
  app_phdr.p_paddr = app_phdr.p_vaddr;
  app_phdr.p_filesz = input_elf_size;
  app_phdr.p_memsz = input_elf_size;
  app_phdr.p_flags = PF_R | PF_W;
  app_phdr.p_align =  0x200000;
  CK_NEQ_PERROR(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0);

  /* Stub loader contents */
  CK_NEQ_PERROR(
      fwrite(loader_x86_64, sizeof(loader_x86_64), 1, output_file), 0);

  /* Packed application contents */
  CK_NEQ_PERROR(fwrite(input_elf, input_elf_size, 1, output_file), 0);

  return 0;
}

static int instrument_func(void *elf_start, Elf64_Sym *func_sym) {
  uint8_t *code = elf_get_sym(elf_start, func_sym);

  uint8_t *code_ptr = code;
  while (code_ptr < code + func_sym->st_size) {
    INSTRUX ix;
    NDSTATUS status = NdDecode(&ix, code_ptr, ND_CODE_64, ND_DATA_64);

    if (!ND_SUCCESS(status)) {
      fprintf(stderr, "instruction decoding failed\n");
      return -1;
    }

    /* Ret opcodes */
    if (ix.PrimaryOpCode == 0xC3 || ix.PrimaryOpCode == 0xCB ||
        ix.PrimaryOpCode == 0xC2 || ix.PrimaryOpCode == 0xCA) {
      verbose(
          "instrumenting ret instruction at offset %d in original binary\n",
          code_ptr - (uint8_t *) elf_start);
      /* 0xCC = int3 (one byte instruction) */
      *code_ptr = (uint8_t) 0xCC;
    }

    code_ptr += ix.Length;
  }

  /* Instrument entry point */
  code[0] = 0xCC;
  return 0;
}

static int apply_inner_encryption(void *elf_start, size_t elf_size,
                                  struct key_info *key_info) {
  const Elf64_Ehdr *ehdr = elf_start;

  verbose("attempting to apply inner encryption (per-function encryption)\n");

  if (ehdr->e_shoff == 0 || !elf_get_sec_by_name(elf_start, ".symtab")) {
    printf("binary is stripped, not applying inner encryption\n");
    return -1;
  }

  const Elf64_Shdr *strtab = elf_get_sec_by_name(elf_start, ".strtab");
  if (strtab == NULL) {
    fprintf(stderr,
            "could not find string table, not applying inner encryption\n");
    return -1;
  }

  ELF_FOR_EACH_SYMBOL(elf_start, sym) {
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    verbose("instrumenting function %s\n",
            elf_get_sym_name(elf_start, sym, strtab));

    instrument_func(elf_start, sym);
  }

  return 0;
}

static void apply_outer_encryption(void *packed_bin_start, void *loader_start,
                                   size_t loader_size, size_t packed_bin_size,
                                   struct key_info *key_info) {
  struct rc4_state rc4;
  rc4_init(&rc4, key_info->key, sizeof(key_info->key));

  verbose("attempting to apply outer encryption (whole-binary encryption)\n");

  /* Obfuscate Key */
  struct key_info obfuscated_key;
  obf_deobf_key(key_info, &obfuscated_key, loader_start, loader_size);

  /* Encrypt the actual binary */
  /* skip the first sizeof(struct key_info) bytes as that has the key itself */
  unsigned char *curr = (unsigned char *) packed_bin_start;
  for (size_t i = 0; i < packed_bin_size; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }

  /* Copy over key_info struct so the loader can decrypt */
  *((struct key_info *) loader_start) = obfuscated_key;
}

static void usage() {
  printf(
      "Kiteshield, an obfuscating packer for x86-64 binaries on Linux\n"
      "Usage: kiteshield [OPTION] INPUT_FILE OUTPUT_FILE\n\n"
      "  -n       don't apply inner encryption (per-function encryption)\n"
      "  -v       verbose\n"
  );
}

int main(int argc, char *argv[]) {
  char *input_bin, *output_bin;
  int use_inner_encryption = 1;

  int c;
  while ((c = getopt (argc, argv, "nv")) != -1) {
    switch (c) {
    case 'n':
      use_inner_encryption = 0;
      break;
    case 'v':
      log_verbose = 1;
      break;
    default:
      usage();
      return -1;
    }
  }

  if (optind + 1 < argc) {
    input_bin = argv[optind];
    output_bin = argv[optind + 1];
  } else {
    usage();
    return -1;
  }

  void *elf_buf;
  size_t elf_buf_size;
  if (read_input_elf(input_bin, &elf_buf, &elf_buf_size) == -1) {
    fprintf(stderr, "error reading input ELF\n");
    return -1;
  }

  struct key_info key_info;
  CK_NEQ_PERROR(getrandom(key_info.key, sizeof(key_info.key), 0), -1);
  verbose("using key ");
  for (int i = 0; i < sizeof(key_info.key); i++) {
    verbose("%02hhx ", key_info.key[i]);
  }
  verbose("for RC4 encryption\n");

  if (use_inner_encryption) {
    if (apply_inner_encryption(elf_buf, elf_buf_size, &key_info) == -1) {
      fprintf(stderr, "could not apply inner encryption\n");
      return -1;
    }
  }

  apply_outer_encryption(elf_buf, loader_x86_64, sizeof(loader_x86_64),
                         elf_buf_size, &key_info);

  FILE *output_elf;
  CK_NEQ_PERROR(output_elf = fopen(output_bin, "w"), NULL);
  CK_NEQ_PERROR(produce_output_elf(output_elf, elf_buf, elf_buf_size), -1);

  CK_NEQ_PERROR(fclose(output_elf), EOF);
  CK_NEQ_PERROR(
      chmod(output_bin, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  printf("output ELF has been written to %s\n", output_bin);
  return 0;
}
