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

static int read_input_elf(char *path, struct mapped_elf *elf)
{
  void *elf_buf;
  size_t size;

  FILE *file;
  CK_NEQ_PERROR(file = fopen(path, "r"), NULL);
  CK_NEQ_PERROR(fseek(file, 0L, SEEK_END), -1);

  CK_NEQ_PERROR(size = ftell(file), -1);
  CK_NEQ_PERROR(elf_buf = malloc(size), NULL);

  CK_NEQ_PERROR(fseek(file, 0L, SEEK_SET), -1);
  CK_NEQ_PERROR(fread(elf_buf, size, 1, file), 0);

  CK_NEQ_PERROR(fclose(file), EOF);

  parse_mapped_elf(elf_buf, size, elf);

  return 0;
}

static int produce_output_elf(
    FILE *output_file,
    struct mapped_elf *elf,
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
  app_phdr.p_filesz = elf->size;
  app_phdr.p_memsz = elf->size;
  app_phdr.p_flags = PF_R | PF_W;
  app_phdr.p_align =  0x200000;
  CK_NEQ_PERROR(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0);

  /* Loader code/data */
  CK_NEQ_PERROR(
      fwrite(loader, loader_size, 1, output_file), 0);

  /* Packed application contents */
  CK_NEQ_PERROR(fwrite(elf->start, elf->size, 1, output_file), 0);

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

static uint64_t get_base_addr(Elf64_Ehdr *ehdr)
{
  /* Return the base address that the binary is to be mapped in at runtime. If
   * statically linked, use absolute addresses (ie. base address = 0).
   * Otherwise, everything is relative to UNPACKED_BIN_LOAD_ADDR. */
  return ehdr->e_type == ET_EXEC ? 0ULL : UNPACKED_BIN_LOAD_ADDR;
}

static int is_instrumentable_jmp(
    INSTRUX *ix,
    uint64_t fcn_start,
    size_t fcn_size,
    uint64_t ix_addr)
{
  /* Indirect jump (eg. jump to value stored in register or at memory location.
   * These must always be instrumented as we have no way at pack-time of
   * knowing where they will hand control, thus the runtime must check them
   * each time and encrypt/decrypt/do nothing as needed.
   */
  if (ix->Instruction == ND_INS_JMPNI)
    return 1;

  /* Jump with (known at pack-time) relative offset, check if it jumps out of
   * its function, if so, it requires instrumentation. */
  if (ix->Instruction == ND_INS_JMPNR || ix->Instruction == ND_INS_Jcc) {
    int64_t displacement = (int64_t) ix->Operands[0].Info.RelativeOffset.Rel;
    uint64_t jmp_dest = ix_addr + displacement;
    if (jmp_dest < fcn_start || jmp_dest > fcn_start + fcn_size)
      return 1;
  }

  return 0;
}

static int process_func(
    struct mapped_elf *elf,
    Elf64_Sym *func_sym,
    struct trap_point_info *tp_info,
    struct function *func_arr,
    struct trap_point *tp_arr,
    struct rc4_key *key)
{
  uint8_t *func_start = elf_get_sym_location(elf, func_sym);
  uint64_t base_addr = get_base_addr(elf->ehdr);
  struct function *fcn = &func_arr[tp_info->nfuncs];

  fcn->start_addr = (void *) (base_addr + func_sym->st_value);
  fcn->len = func_sym->st_size;
#ifdef DEBUG_OUTPUT
  strncpy(fcn->name, elf_get_sym_name(elf, func_sym), sizeof(fcn->name));
  fcn->name[sizeof(fcn->name) - 1] = '\0';
#endif

  uint8_t *code_ptr = func_start;
  while (code_ptr < func_start + func_sym->st_size) {
    INSTRUX ix;
    NDSTATUS status = NdDecode(&ix, code_ptr, ND_CODE_64, ND_DATA_64);
    if (!ND_SUCCESS(status)) {
      fprintf(stderr, "instruction decoding failed\n");
      return -1;
    }
    size_t off = (size_t) (code_ptr - func_start);

    int is_jmp_to_instrument = is_instrumentable_jmp(
        &ix,
        base_addr + func_sym->st_value,
        func_sym->st_size,
        base_addr + func_sym->st_value + off);
    int is_ret_to_instrument =
      ix.Instruction == ND_INS_RETF || ix.Instruction == ND_INS_RETN;

    if (is_jmp_to_instrument || is_ret_to_instrument) {
      void *addr = (void *)
                   (base_addr + func_sym->st_value + off);
      verbose("\tinstrumenting %s at vaddr %p\n",
          ix.Mnemonic, addr, off);

      struct trap_point *tp =
        (struct trap_point *) &tp_arr[tp_info->ntps++];
      tp->addr = addr;
      tp->type = is_ret_to_instrument ? TP_RET : TP_JMP;
      tp->value = *code_ptr;
      tp->fcn_i = tp_info->nfuncs;
      *code_ptr = INT3;
    }

    code_ptr += ix.Length;
  }

  /* Instrument entry point */
  struct trap_point *tp =
    (struct trap_point *) &tp_arr[tp_info->ntps++];
  tp->addr = (void *) base_addr + func_sym->st_value;
  tp->type = TP_FCN_ENTRY;
  tp->value = *func_start;
  tp->fcn_i = tp_info->nfuncs;

  encrypt_memory_range(key, func_start, func_sym->st_size);

  *func_start = INT3;

  tp_info->nfuncs++;

  return 0;
}

static int apply_inner_encryption(
    struct mapped_elf *elf,
    struct rc4_key *key,
    struct trap_point_info **tp_info)
{
  verbose("applying inner encryption (per-function encryption)\n");

  if (elf->ehdr->e_shoff == 0 || !elf->symtab) {
    printf("binary is stripped, not applying inner encryption\n");
    return -1;
  }

  if (!elf->strtab) {
    fprintf(stderr,
        "could not find string table, not applying inner encryption\n");
    return -1;
  }

  CK_NEQ_PERROR(*tp_info = malloc(sizeof(**tp_info)), NULL);
  (*tp_info)->nfuncs = 0;
  (*tp_info)->ntps = 0;

  /* "16 MiB ought to be enough for anybody" */
  struct function *fcn_arr;
  CK_NEQ_PERROR(fcn_arr = malloc(1<<24), NULL);

  struct trap_point *tp_arr;
  CK_NEQ_PERROR(tp_arr = malloc(1<<24), NULL);

  ELF_FOR_EACH_SYMBOL(elf, sym) {
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    uint8_t *func_code_start = elf_get_sym_location(elf, sym);
    INSTRUX ix;
    NDSTATUS status = NdDecode(&ix, func_code_start, ND_CODE_64, ND_DATA_64);
    if (!ND_SUCCESS(status)) {
      fprintf(stderr, "instruction decoding failed");
      return -1;
    }

    /* Skip instrumenting/encrypting functions in cases where it simply will
     * not work or has the potential to mess things up. Specifically, this
     * means we don't instrument functions that:
     *
     *  * Are not in .text (eg. stuff in .init)
     *
     *  * Have an address of 0 (stuff that needs to be relocated, this should
     *  be covered by the point above anyways, but check to be safe)
     *
     *  * Have a size of 0 (stuff in crtstuff.c that was compiled with
     *  -finhibit-size-directive has a size of 0, thus we can't instrument)
     *
     *  * Have a size less than 2 (superset of above point). Instrumentation
     *  requires inserting at least two int3 instructions, each of which is one
     *  byte.
     *
     *  * Start with an instruction that modifies control flow (ie. jmp/ret)
     *  kiteshield instruments the start of every function AND every out of
     *  function jmp/return, so instrumenting these would require putting two
     *  trap points at the same address. It's theoretically possible to support
     *  this in the runtime, but would add a large amount of complexity to it
     *  in order to support encrypting the small amount of hand coded asm
     *  functions in glibc that are like this.
     */
    if (!elf_sym_in_text(elf, sym)) {
      verbose("not encrypting function %s as it's not in .text\n",
              elf_get_sym_name(elf, sym));
      continue;
    } else if (sym->st_value == 0 ||
               sym->st_size < 2) {
      verbose(
          "not encrypting of function %s due to its address or size\n",
          elf_get_sym_name(elf, sym));
      continue;
    } else if (ix.Instruction == ND_INS_JMPNI ||
               ix.Instruction == ND_INS_JMPNR ||
               ix.Instruction == ND_INS_Jcc ||
               ix.Instruction == ND_INS_CALLNI ||
               ix.Instruction == ND_INS_CALLNR) {
      verbose("not encrypting function %s due to first instruction being jmp/ret\n",
              elf_get_sym_name(elf, sym));
      continue;
    }

    /* Statically linked binaries contain several function symbols that alias
     * eachother (_IO_vfprintf and fprintf in glibc for instance). Detect and
     * skip them here as to not double-encrypt.
     */
    const Elf64_Sym *alias = elf_get_first_fcn_alias(elf, sym);
    if (alias) {
        verbose(
            "not encrypting function %s as it aliases %s\n",
            elf_get_sym_name(elf, sym), elf_get_sym_name(elf, alias));
        continue;
    }

    verbose("instrumenting and encrypting function %s\n",
        elf_get_sym_name(elf, sym));

    if (process_func(elf, sym, *tp_info, fcn_arr, tp_arr, key) == -1) {
      fprintf(stderr, "error instrumenting function %s\n",
              elf_get_sym_name(elf, sym));
      return -1;
    }
  }

  size_t tp_arr_sz = sizeof(struct trap_point) * (*tp_info)->ntps;
  size_t fcn_arr_sz = sizeof(struct function) * (*tp_info)->nfuncs;
  CK_NEQ_PERROR(
      *tp_info = realloc(*tp_info,
              sizeof(struct trap_point_info) + tp_arr_sz + fcn_arr_sz),
      NULL);

  memcpy((*tp_info)->data, tp_arr, tp_arr_sz);
  memcpy((*tp_info)->data + tp_arr_sz, fcn_arr, fcn_arr_sz);

  free(tp_arr);
  free(fcn_arr);

  return 0;
}

static int apply_outer_encryption(
    struct mapped_elf *elf,
    void *loader_start,
    size_t loader_size,
    struct rc4_key *key)
{
  verbose("applying outer encryption (whole-binary encryption)\n");

  /* Encrypt the actual binary */
  encrypt_memory_range(key, elf->start, elf->size);

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
                        sizeof(struct trap_point) * tp_info->ntps +
                        sizeof(struct function) * tp_info->nfuncs;
  void *loader_tp_info = malloc(sizeof(loader_x86_64) + tp_info_size);

  memcpy(loader_tp_info, loader_x86_64, sizeof(loader_x86_64));

  /* subtract sizeof(struct trap_point_info) here to ensure we overwrite the non
   * flexible-array portion of the struct that the linker actually puts in the
   * code. */
  memcpy(loader_tp_info + sizeof(loader_x86_64) - sizeof(struct trap_point_info),
         tp_info, tp_info_size);

  *new_size = sizeof(loader_x86_64) + tp_info_size;
  verbose(
      "injected trap point info into loader old size: %u bytes new size: %u bytes\n",
      sizeof(loader_x86_64), *new_size);
  return loader_tp_info;
}

/* Remove everything not needed for program execution from the binary */
static int full_strip(struct mapped_elf *elf)
{
  Elf64_Phdr *curr_phdr = elf->phdr_tbl;
  size_t new_size = 0;
  verbose("stripping input binary\n");

  /* Calculate minimum size needed to contain all program headers */
  for (int i = 0; i < elf->ehdr->e_phnum; i++) {
    size_t seg_end = curr_phdr->p_offset + curr_phdr->p_filesz;
    if (seg_end > new_size)
      new_size = seg_end;
    curr_phdr++;
  }

  if (elf->ehdr->e_shoff >= new_size) {
    elf->ehdr->e_shoff = 0;
    elf->ehdr->e_shnum = 0;
    elf->ehdr->e_shstrndx = 0;
  } else {
    fprintf(stdout,
            "warning: could not strip out all section info from binary\n");
    fprintf(stdout, "output binary may be corrupt!\n");
  }

  void *new_elf = malloc(new_size);
  CK_NEQ_PERROR(new_elf, NULL);
  memcpy(new_elf, elf->start, new_size);
  free(elf->start);
  parse_mapped_elf(new_elf, new_size, elf);

  return 0;
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
  char *input_path, *output_path;
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
    input_path = argv[optind];
    output_path = argv[optind + 1];
  } else {
    usage();
    return -1;
  }

  /* Read ELF to be packed */
  struct mapped_elf elf;
  ret = read_input_elf(input_path, &elf);
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
    ret = apply_inner_encryption(&elf, &key, &tp_info);
    if (ret == -1) {
      fprintf(stderr, "could not apply inner encryption\n");
      return -1;
    }

    /* Inject trap point info into loader */
    loader_tp_info = inject_tp_info(tp_info, &loader_tp_info_size);
  }

  /* Fully strip binary */
  if (full_strip(&elf) == -1) {
    fprintf(stderr, "could not strip binary");
    return -1;
  }

  /* Apply outer encryption */
  ret = apply_outer_encryption(&elf, loader_tp_info, loader_tp_info_size, &key);
  if (ret == -1) {
    fprintf(stderr, "could not apply outer encryption");
    return -1;
  }

  /* Write output ELF */
  FILE *output_file;
  CK_NEQ_PERROR(output_file = fopen(output_path, "w"), NULL);
  ret = produce_output_elf(output_file, &elf, loader_tp_info,
                           loader_tp_info_size);
  if (ret == -1) {
    fprintf(stderr, "could not produce output ELF\n");
    return -1;
  }

  CK_NEQ_PERROR(fclose(output_file), EOF);
  CK_NEQ_PERROR(
      chmod(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  printf("output ELF has been written to %s\n", output_path);
  return 0;
}

