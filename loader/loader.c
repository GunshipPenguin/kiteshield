#include <elf.h>

#include "common/include/defs.h"
#include "common/include/rc4.h"
#include "common/include/key_utils.h"

#include "loader/include/syscall_defines.h"
#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/elf_auxv.h"
#include "loader/include/syscalls.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

#define PAGE_ALIGN_DOWN(ptr) ((ptr) & PAGE_MASK)
#define PAGE_ALIGN_UP(ptr) ((((ptr) - 1) & PAGE_MASK) + PAGE_SIZE)
#define PAGE_OFFSET(ptr) (ptr & ~(PAGE_MASK))

struct key_info key_info __attribute__((section(".key_info")));

static void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr)
{
  /* Same rounding logic as in map_load_section_from_fd, see comment below.
   * Note that we don't need a separate mmap here for bss if memsz > filesz
   * as we map an anonymous region and copy into it rather than mapping from
   * an fd (ie. we can just not touch the remaining space and it will be full
   * of zeros by default).
   */
  void *addr = mmap((void *) (UNPACKED_BIN_LOAD_ADDR +
                              PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                    phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr),
                    PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF(addr == MAP_FAILED, "mmap failure");
  DEBUG_FMT("mapping LOAD section from packed binary at %p", addr);

  /* Copy data from the packed binary */
  char *curr_addr = addr;
  for (Elf64_Off f_off = PAGE_ALIGN_DOWN(phdr.p_offset);
       f_off < phdr.p_offset + phdr.p_filesz;
       f_off++) {
    (*curr_addr++) = *((char *) elf_start + f_off);
  }

  /* Set correct permissions (change from -w-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0)  |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
  DIE_IF(mprotect(addr, phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), prot) < 0,
         "mprotect error");
  return addr;
}

static void *map_load_section_from_fd(int fd, Elf64_Phdr phdr)
{
  int prot = 0;
  if (phdr.p_flags & PF_R)
    prot |= PROT_READ;
  if (phdr.p_flags & PF_W)
    prot |= PROT_WRITE;
  if (phdr.p_flags & PF_X)
    prot |= PROT_EXEC;

  /* mmap requires that the addr and offset fields are multiples of the page
   * size. Since that may not be the case for the p_vaddr and p_offset fields
   * in an ELF binary, we have to do some math to ensure the passed in
   * address/offset are multiples of the page size.
   *
   * To calculate the load address, we start at the interpreter base address
   * (which is a multiple of the page size itself), and add p_vaddr rounded
   * down to the nearest page size multiple. We round down the offset parameter
   * to the nearest page size multiple in the same way. Since both the offset
   * and virtual address are guaranteed to be congruent modulo the page size
   * (as per the ELF standard), this will result in them both being rounded
   * down by the same amount, and the produced mapping will be correct.
   */
  void *addr = mmap((void *) (INTERP_LOAD_ADDR +
                              PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                    phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr),
                    prot, MAP_PRIVATE | MAP_FIXED,
                    fd,
                    PAGE_ALIGN_DOWN(phdr.p_offset));
  DIE_IF(addr == MAP_FAILED,
         "mmap failure while mapping load section from fd");

  /* If p_memsz > p_filesz, the remaining space must be filled with zeros
   * (Usually the .bss section), map extra anon pages if this is the case. */
  if (phdr.p_memsz > phdr.p_filesz) {
    void *extra_space = mmap(addr + PAGE_ALIGN_UP(phdr.p_filesz),
                             phdr.p_memsz - phdr.p_filesz, prot,
                             MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    DIE_IF(extra_space == MAP_FAILED,
           "mmap failure while mapping extra space for static vars");
  }

  DEBUG_FMT("mapped LOAD section from fd at %p", addr);
  return addr;
}

static void map_interp(void *path, void **entry, void **interp_base)
{
  DEBUG_FMT("mapping INTERP ELF at path %s", path);
  int interp_fd = open(path, O_RDONLY, 0);
  DIE_IF(interp_fd == -1, "could not open interpreter binary");

  Elf64_Ehdr ehdr;
  DIE_IF(read(interp_fd, &ehdr, sizeof(ehdr)) < 0,
         "read failure while reading interpreter binary header");
  *entry = ((void *) INTERP_LOAD_ADDR + ehdr.e_entry);

  int base_addr_set = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;

    off_t lseek_res = lseek(interp_fd, ehdr.e_phoff + i * sizeof(Elf64_Phdr),
                            SEEK_SET);
    DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

    size_t read_res = read(interp_fd, &curr_phdr, sizeof(curr_phdr));
    DIE_IF(read_res < 0, "read failure while mapping interpreter");

    /* We shouldn't be dealing with any non PT_LOAD segments here */
    if (curr_phdr.p_type != PT_LOAD)
      continue;

    void *addr = map_load_section_from_fd(interp_fd, curr_phdr);

    if (!base_addr_set){
      DEBUG_FMT("interpreter base address is %p", addr);
      *interp_base = addr;
      base_addr_set = 1;
    }
    DEBUG_FMT("mapped interpreter segment from fd with offset %p",
              curr_phdr.p_offset);
  }
}

static void map_elf_from_mem(
    void *elf_start,
    void **interp_entry,
    void **interp_base)
{
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  Elf64_Phdr *interp_hdr = NULL;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (curr_phdr->p_type == PT_LOAD)
      map_load_section_from_mem(elf_start, *curr_phdr);
    else if (curr_phdr->p_type == PT_INTERP)
      interp_hdr = curr_phdr;

    curr_phdr++;
  }

  if (interp_hdr)
    map_interp(elf_start + interp_hdr->p_offset, interp_entry, interp_base);
}

static void replace_auxv_ent(unsigned long long *auxv_start,
                             unsigned long long label,
                             unsigned long long value)
{
  unsigned long long *curr_ent = auxv_start;
  while (*curr_ent != label && *curr_ent != AT_NULL) curr_ent += 2;
  DIE_IF_FMT(*curr_ent == AT_NULL, "could not find auxv entry %d", label);

  *(++curr_ent) = value;
  DEBUG_FMT("replaced auxv entry %llu with value %llu (0x%p)", label, value,
            value);
}

static void setup_auxv(
    void *argv_start,
    void *entry,
    void *phdr_addr,
    void *interp_base,
    unsigned long long phnum)
{
  unsigned long long *auxv_start = argv_start;

#define ADVANCE_PAST_NEXT_NULL(ptr) \
  while (*(++ptr) != NULL) ;        \
  ptr++;

  ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
  ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */

  DEBUG_FMT("taking %p as auxv start", auxv_start);
  replace_auxv_ent(auxv_start, AT_UID, 0);
  replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long) entry);
  replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long) phdr_addr);
  replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long) interp_base);
  replace_auxv_ent(auxv_start, AT_PHNUM, phnum);
}

static void decrypt_packed_bin(
    void *packed_bin_start,
    size_t packed_bin_size,
    void *loader_start,
    size_t loader_size)
{
  struct key_info actual_key;
  obf_deobf_key(&key_info, &actual_key, loader_start, loader_size);

  struct rc4_state rc4;
  rc4_init(&rc4, actual_key.key, sizeof(actual_key.key));

#ifdef DEBUG_OUTPUT
  minimal_printf(1, KITESHIELD_PREFIX "RC4 decrypting binary with key ");
  for (int i = 0; i < KEY_SIZE; i++) {
    minimal_printf(1, "%hhx ", actual_key.key[i]);
  }
  minimal_printf(1, "\n");
#endif

  unsigned char *curr = packed_bin_start;
  for (int i = 0; i < packed_bin_size; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }

  DEBUG_FMT("decrypted %u bytes", packed_bin_size);
}

/* Load the packed binary, returns the address to hand control to when done */
void *load(void *entry_stacktop)
{
  /* As per the SVr4 ABI */
  /* int argc = (int) *((unsigned long long *) entry_stacktop); */
  char **argv = ((char **) entry_stacktop) + 1;

  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *) LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)
                            (LOADER_ADDR + us_ehdr->e_phoff);

  /* The PHDR in our binary corresponding to the encrypted app */
  Elf64_Phdr *packed_bin_phdr = loader_phdr + 1;

  /* The EHDR of the actual application to be run (encrypted until
   * decrypt_packed_bin is called)
   */
  Elf64_Ehdr *packed_bin_ehdr = (Elf64_Ehdr *) (packed_bin_phdr->p_vaddr);

  /* The first ELF segment (loader code) includes the ehdr and two phdrs,
   * adjust loader code start and size accordingly */
  size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  decrypt_packed_bin((void *) packed_bin_phdr->p_vaddr,
                     packed_bin_phdr->p_memsz,
                     (void *) loader_phdr->p_vaddr + hdr_adjust,
                     loader_phdr->p_memsz - hdr_adjust);

  void *interp_entry;
  void *interp_base;
  map_elf_from_mem(packed_bin_ehdr, &interp_entry, &interp_base);
  setup_auxv(argv,
             (void *) (UNPACKED_BIN_LOAD_ADDR + packed_bin_ehdr->e_entry),
             (void *) (UNPACKED_BIN_LOAD_ADDR + packed_bin_ehdr->e_phoff),
             interp_base, packed_bin_ehdr->e_phnum);

  DEBUG("finished mapping binary into memory");
  DEBUG_FMT("preparing to fork and pass control in child to ld.so at %p",
            interp_entry);

  return interp_entry;
}

