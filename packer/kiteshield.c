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

#include "common/include/rc4.h"
#include "common/include/key_utils.h"
#include "common/include/defs.h"
#include "packer/include/elfutils.h"

#include "loader/out/loader_header.h"

#define CK_NEQ_PERROR(stmt, err)                                              \
  do {                                                                        \
    if ((stmt) == err) {                                                      \
      perror(#stmt);                                                          \
      return -1;                                                              \
    }                                                                         \
  } while(0)

static int log_verbose = 0;

/* Needs to be defined for bddisasm */
int nd_vsnprintf_s(
    char *buffer,
    size_t sizeOfBuffer,
    size_t count,
    const char *format,
    va_list argptr)
{
  return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}

/* Needs to be defined for bddisasm */
void* nd_memset(void *s, int c, size_t n)
{
  return memset(s, c, n);
}

static void verbose(char *fmt, ...)
{
  if (!log_verbose)
    return;

  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);
}

static int read_input_elf(char *path, void **buf_ptr, size_t *elf_buf_size)
{
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

static int produce_output_elf(
    FILE *output_file,
    void *input_elf,
    size_t input_elf_size,
    void *loader,
    size_t loader_size)
{
  /* The entry address is located right after the struct rc4_key (used for
   * passing decryption key and other info to loader), which is the first
   * sizeof(struct rc4_key) bytes of the loader code (guaranteed by the linker
   * script) */
  Elf64_Addr entry_vaddr = LOADER_ADDR +
                           sizeof(Elf64_Ehdr) +
                           (sizeof(Elf64_Phdr) * 2) +
                           sizeof(struct rc4_key);
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

  /* Size of the first segment include the size of the ehdr and two phdrs */
  size_t hdrs_size = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  /* Program header for loader */
  Elf64_Phdr loader_phdr;
  loader_phdr.p_type = PT_LOAD;
  loader_phdr.p_offset = 0;
  loader_phdr.p_vaddr = LOADER_ADDR;
  loader_phdr.p_paddr = loader_phdr.p_vaddr;
  loader_phdr.p_filesz = loader_size + hdrs_size;
  loader_phdr.p_memsz = loader_size + hdrs_size;
  loader_phdr.p_flags = PF_R | PF_W | PF_X;
  loader_phdr.p_align = 0x200000;
  CK_NEQ_PERROR(fwrite(&loader_phdr, sizeof(loader_phdr), 1, output_file), 0);

  /* Program header for packed application */
  int app_offset = ftell(output_file) + sizeof(Elf64_Phdr) + loader_size;
  Elf64_Phdr app_phdr;
  app_phdr.p_type = PT_LOAD;
  app_phdr.p_offset = app_offset;
  app_phdr.p_vaddr = PACKED_BIN_ADDR + app_offset; /* Keep vaddr aligned */
  app_phdr.p_paddr = app_phdr.p_vaddr;
  app_phdr.p_filesz = input_elf_size;
  app_phdr.p_memsz = input_elf_size;
  app_phdr.p_flags = PF_R | PF_W;
  app_phdr.p_align =  0x200000;
  CK_NEQ_PERROR(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0);

  /* Loader code/data */
  CK_NEQ_PERROR(
      fwrite(loader, loader_size, 1, output_file), 0);

  /* Packed application contents */
  CK_NEQ_PERROR(fwrite(input_elf, input_elf_size, 1, output_file), 0);

  return 0;
}

static void encrypt_memory_range(struct rc4_key *key, void *start, size_t len)
{
  struct rc4_state rc4;
  rc4_init(&rc4, key->bytes, sizeof(key->bytes));

  uint8_t *curr = start;
  for (size_t i = 0; i < len; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }
}

static int process_func(
    void *elf_start,
    Elf64_Sym *func_sym,
    struct trap_point_info *tp_info,
    struct rc4_key *key)
{
  uint8_t *func_start = elf_get_sym(elf_start, func_sym);

  uint8_t *code_ptr = func_start;
  while (code_ptr < func_start + func_sym->st_size) {
    INSTRUX ix;
    NDSTATUS status = NdDecode(&ix, code_ptr, ND_CODE_64, ND_DATA_64);

    if (!ND_SUCCESS(status)) {
      fprintf(stderr, "instruction decoding failed\n");
      return -1;
    }

    /* Ret opcodes */
    if (ix.PrimaryOpCode == 0xC3 || ix.PrimaryOpCode == 0xCB ||
        ix.PrimaryOpCode == 0xC2 || ix.PrimaryOpCode == 0xCA) {
      size_t off = (size_t) (code_ptr - func_start);
      void *addr = (void *)
                   (UNPACKED_BIN_LOAD_ADDR + func_sym->st_value + off);
      verbose("instrumenting ret instruction at vaddr %p, offset in func %u\n",
              addr, off);

      struct trap_point *tp = &tp_info->arr[tp_info->num++];
      tp->addr = addr;
      tp->value = *code_ptr;
      tp->fcn.start_addr = (void *)
                            (UNPACKED_BIN_LOAD_ADDR + func_sym->st_value);
      tp->fcn.len = func_sym->st_size;
      tp->is_ret = 1;

      *code_ptr = INT3;
    }

    code_ptr += ix.Length;
  }

  struct trap_point *tp = &tp_info->arr[tp_info->num++];
  tp->addr = (void *) UNPACKED_BIN_LOAD_ADDR + func_sym->st_value;
  tp->value = *func_start;
  tp->fcn.start_addr = (void *)
                        (UNPACKED_BIN_LOAD_ADDR + func_sym->st_value);
  tp->fcn.len = func_sym->st_size;
  tp->is_ret = 0;

  verbose("encrypting function at %p, len %u\n", func_sym->st_value, func_sym->st_size);
  encrypt_memory_range(key, func_start, func_sym->st_size);

  /* Instrument entry point */
  *func_start = INT3;

  return 0;
}

static int apply_inner_encryption(
    void *elf_start,
    size_t elf_size,
    struct rc4_key *key,
    struct trap_point_info **tp_info)
{
  verbose("attempting to apply inner encryption (per-function encryption)\n");
  const Elf64_Ehdr *ehdr = elf_start;

  const Elf64_Shdr *text_shdr = elf_get_sec_by_name(elf_start, ".text");
  if (!text_shdr) {
    fprintf(stderr, "Could not find .text section");
    return -1;
  }

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

  *tp_info = malloc(4096);
  (*tp_info)->num = 0;
  ELF_FOR_EACH_SYMBOL(elf_start, sym) {
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    /* Skip instrumenting/encrypting functions in cases where it simply will
     * not work or has the potential to mess things up. Specifically, this
     * means we don't instrument functions that:
     *
     *  - Are not in .text (eg. stuff in .init)
     *  - Have an address of 0 (stuff that needs to be relocated, this should
     *    be covered by the point above anyways, but check to be safe)
     *  - Have a size of 0 (stuff in crtstuff.c that was compiled with
     *    -finhibit-size-directive has a size of 0, thus we can't instrument)
     *  - Have a size less than 2 (superset of above point). Instrumentation
     *    requires inserting at least two int3 instructions, each of which is
     *    one byte.
     */
    if (!elf_sec_contains_sym(text_shdr, sym) ||
        sym->st_value == 0 ||
        sym->st_size < 2) {
      verbose("skipping instrumentation of function %s\n",
              elf_get_sym_name(elf_start, sym, strtab));
      continue;
    }

    verbose("instrumenting function %s\n",
        elf_get_sym_name(elf_start, sym, strtab));

    if (process_func(elf_start, sym, *tp_info, key) == -1) {
      fprintf(stderr, "error instrumenting function %s\n",
              elf_get_sym_name(elf_start, sym, strtab));
    }
  }

  return 0;
}

static int apply_outer_encryption(
    void *packed_bin_start,
    void *loader_start,
    size_t loader_size,
    size_t packed_bin_size,
    struct rc4_key *key)
{
  verbose("attempting to apply outer encryption (whole-binary encryption)\n");

  /* Encrypt the actual binary */
  encrypt_memory_range(key, packed_bin_start, packed_bin_size);

  /* Obfuscate Key */
  struct rc4_key obfuscated_key;
  obf_deobf_key(key, &obfuscated_key, loader_start, loader_size);

  /* Copy over obfuscated key so the loader can decrypt */
  *((struct rc4_key *) loader_start) = obfuscated_key;

  return 0;
}

static void *inject_tp_info(struct trap_point_info *tp_info, size_t *new_size)
{
  size_t tp_info_size = sizeof(struct trap_point_info) +
                    sizeof(struct trap_point) * tp_info->num;
  void *loader_tp_info = malloc(sizeof(loader_x86_64) + tp_info_size);

  memcpy(loader_tp_info, loader_x86_64, sizeof(loader_x86_64));

  /* subtract sizeof(struct trap_point_info) here to ensure we overwrite the non
   * flexible-array portion of the struct that the linker actually puts in the
   * code. */
  memcpy(loader_tp_info + sizeof(loader_x86_64) - sizeof(struct trap_point_info),
         tp_info, tp_info_size);

  *new_size = sizeof(loader_x86_64) + tp_info_size;
  verbose(
      "Injected trap point info into loader old size: %u new size: %u\n",
      sizeof(loader_x86_64), *new_size);
  return loader_tp_info;
}

static void usage()
{
  printf(
      "Kiteshield, an obfuscating packer for x86-64 binaries on Linux\n"
      "Usage: kiteshield [OPTION] INPUT_FILE OUTPUT_FILE\n\n"
      "  -n       don't apply inner encryption (per-function encryption)\n"
      "  -v       verbose\n"
  );
}

int main(int argc, char *argv[])
{
  char *input_bin, *output_bin;
  int use_inner_encryption = 1;
  int c;
  int ret;

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


  /* Read ELF to be packed */
  void *elf_buf;
  size_t elf_buf_size;
  ret = read_input_elf(input_bin, &elf_buf, &elf_buf_size);
  if (ret == -1) {
    fprintf(stderr, "error reading input ELF\n");
    return -1;
  }

  /* Generate key */
  struct rc4_key key;
  CK_NEQ_PERROR(getrandom(key.bytes, sizeof(key.bytes), 0), -1);
  verbose("using key ");
  for (int i = 0; i < sizeof(key.bytes); i++) {
    verbose("%02hhx ", key.bytes[i]);
  }
  verbose("for RC4 encryption\n");

  /* Apply inner encryption if requested */
  size_t loader_tp_info_size = sizeof(loader_x86_64);
  void *loader_tp_info = loader_x86_64;
  if (use_inner_encryption) {
    struct trap_point_info *tp_info = NULL;
    ret = apply_inner_encryption(elf_buf, elf_buf_size, &key, &tp_info);
    if (ret == -1) {
      fprintf(stderr, "could not apply inner encryption\n");
      return -1;
    }

    /* Inject trap point info into loader */
    loader_tp_info = inject_tp_info(tp_info, &loader_tp_info_size);
  }

  /* Apply outer encryption */
  ret = apply_outer_encryption(elf_buf, loader_tp_info, loader_tp_info_size,
                               elf_buf_size, &key);
  if (ret == -1) {
    fprintf(stderr, "could not apply outer encryption");
    return -1;
  }

  /* Write output ELF */
  FILE *output_elf;
  CK_NEQ_PERROR(output_elf = fopen(output_bin, "w"), NULL);
  ret = produce_output_elf(output_elf, elf_buf, elf_buf_size,
                           loader_tp_info, loader_tp_info_size);
  if (ret == -1) {
    fprintf(stderr, "could not produce output ELF\n");
    return -1;
  }

  CK_NEQ_PERROR(fclose(output_elf), EOF);
  CK_NEQ_PERROR(
      chmod(output_bin, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  printf("output ELF has been written to %s\n", output_bin);
  return 0;
}

