#include <elf.h>

#include "common/include/defs.h"
#include "loaders/arch/x86_64/include/syscall_defines.h"
#include "loaders/platform_independent/include/arch_typedefs.h"
#include "loaders/platform_independent/include/debug.h"
#include "loaders/platform_independent/include/elf_auxv.h"
#include "loaders/platform_independent/include/syscalls.h"

/* Base address to copy the application to before launching */
#define ENCRYPTED_APP_LOAD_ADDR 0x800000000ULL
#define INTERP_LOAD_ADDR 0xB00000000ULL

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr) {
  void *addr = mmap((void *) ENCRYPTED_APP_LOAD_ADDR + phdr.p_vaddr,
                    phdr.p_memsz,
                    PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF(addr == MAP_FAILED, "mmap failure");

  DEBUG_FMT("mapping LOAD section from packed binary at 0x%p", addr);

  /* When we map a section of the packed binary, the contents are copied */
  char *curr_addr = addr;
  for (Elf64_Off f_off = (Elf64_Addr) phdr.p_offset;
       f_off < phdr.p_offset + phdr.p_filesz; f_off++) {
    *(curr_addr++) = *((char *) elf_start + f_off);
  }

  /* Set correct permissions (change from -W-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0)  |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);

  size_t memsz = (phdr.p_memsz & PAGE_MASK) + PAGE_SIZE;
  int res = mprotect(addr, memsz, prot);
  DIE_IF(res < 0, "mprotect error");

  return addr;
}

void *map_load_section_from_fd(int fd, Elf64_Phdr phdr) {
  int prot = 0;
  if (phdr.p_flags & PF_R) {
    prot |= PROT_READ;
  }
  if (phdr.p_flags & PF_W) {
    prot |= PROT_WRITE;
  }
  if (phdr.p_flags & PF_X) {
    prot |= PROT_EXEC;
  }

  /* mmap requires that the addr and offset fields are multiples of the page
   * size. Since that may not be the case for the p_vaddr and p_offset fields
   * in an ELF binary, we have to do some grungy work to ensure the passed in
   * addr/offset are multipls of the page size.
   *
   * To calculate the load address, we start at the interpreter base address
   * (which is a multiple of the page size itself), and add p_vaddr rounded
   * down to the nearest page size multiple. We round down the offset parameter
   * to the nearest page size multiple in the same way. Since both the offset
   * and virtual address are guaranteed to be congruent modulo the page size
   * (as per the ELF standard), this will result in them both being rounded
   * down by the same amount, and the produced mapping will be correct.
   */
  void *load_addr = (void *) (INTERP_LOAD_ADDR + (phdr.p_vaddr & PAGE_MASK));
  Elf64_Off load_off = phdr.p_offset & PAGE_MASK;

  void *addr = mmap(load_addr, phdr.p_memsz, prot, MAP_PRIVATE | MAP_FIXED, fd, load_off);
  DIE_IF(addr == MAP_FAILED, "mmap failure while mapping load section from fd");

  DEBUG_FMT("mapped LOAD section from fd at %p", addr);
  return load_addr;
}

void map_interp(void *path, void **entry, void **interp_base) {
  DEBUG_FMT("mapping INTERP ELF at path %s", path);
  int interp_fd = open(path, O_RDONLY, 0);

  if (interp_fd < -1) {
    DEBUG("Could not open interpreter ELF");
    exit(1);
  }

  Elf64_Ehdr ehdr;
  if (read(interp_fd, &ehdr, sizeof(ehdr)) < 0) {
    DEBUG("read failure while mapping interpreter");
    exit(1);
  }

  int base_addr_set = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;

    off_t lseek_res = lseek(interp_fd, ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
    DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

    size_t read_res = read(interp_fd, &curr_phdr, sizeof(curr_phdr));
    DIE_IF(read_res < 0, "read failure while mapping interpreter");

    /* We shouldn't be dealing with any non PT_LOAD segments here */
    if (curr_phdr.p_type != PT_LOAD)
      continue;

    void *addr = map_load_section_from_fd(interp_fd, curr_phdr);
    if ((curr_phdr.p_vaddr <= ehdr.e_entry) &&
        (curr_phdr.p_vaddr + curr_phdr.p_memsz >= ehdr.e_entry)) {
          *entry = (addr - curr_phdr.p_vaddr) + ehdr.e_entry;
          DEBUG_FMT("Interpreter entry address is 0x%p", *entry);
    }

    if (!base_addr_set){
      DEBUG_FMT("Interpreter base address is 0x%p", addr);
      *interp_base = addr;
      base_addr_set = 1;
    }
    DEBUG_FMT("Mapped interpreter segment from fd with offset %p",
              curr_phdr.p_offset);
  }
}

void map_elf_from_mem(void *elf_start, void **entry, void **phdr_addr,
                      void **interp_base) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;
  int first_load_segment = 1;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  Elf64_Phdr *interp_hdr = NULL;
  int i;
  for (i = 0; i < ehdr->e_phnum; i++) {
    if (curr_phdr->p_type == PT_LOAD) {
        void *addr = map_load_section_from_mem(elf_start, *curr_phdr);

        /* If this is the first load segment, assume that it starts at an
         * an offset of 0 in the original ELF, and contains the program header
         * table. This isn't totally standards compliant, but is an assumption
         * the Linux kernel makes. See linux/fs/binfmt_elf.c. */
        if (first_load_segment) {
          *phdr_addr = addr + ehdr->e_phoff;
          DEBUG_FMT("Packed ELF load segment at 0x%p", phdr_addr);
          first_load_segment = 0;
        }

        /* If this section contains the entry point, set *entry */
        if ((curr_phdr->p_vaddr <= ehdr->e_entry) &&
            (curr_phdr->p_vaddr + curr_phdr->p_memsz >= ehdr->e_entry)) {
          *entry = addr + ehdr->e_entry;
          DEBUG_FMT("Packed ELF entry address is 0x%p", *entry);
        }
    } else if (curr_phdr->p_type == PT_INTERP) {
      interp_hdr = curr_phdr;
    }
    curr_phdr++;
  }

  if (interp_hdr) {
    map_interp(elf_start + interp_hdr->p_offset, entry, interp_base);
  }
}

void replace_auxv_ent(unsigned long long *auxv_start,
                      unsigned long long label, unsigned long long value) {
  unsigned long long *curr_ent = auxv_start;
  while (*curr_ent != label && *curr_ent != AT_NULL) curr_ent += 2;
  DIE_IF_FMT(*curr_ent == AT_NULL, "Could not find auxv entry %d", label);

  *(++curr_ent) = value;
  DEBUG_FMT("Replaced auxv entry %d with value %l", label, value);
}

void setup_auxv(void *argv_start, void *entry, void *phdr_addr,
                void *interp_base) {
  unsigned long long *auxv_start = argv_start;

#define ADVANCE_PAST_NEXT_NULL(ptr) \
  while (*(++ptr) != NULL) ;\
  ptr++;

  ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
  ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */

  DEBUG_FMT("Taking %p as auxv start", auxv_start);
  replace_auxv_ent(auxv_start, AT_UID, 0);
  replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long) entry);
  replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long) phdr_addr);
  replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long) interp_base);
}

void load(void *entry_stacktop) {
  /* As per the SVr4 ABI */
  int argc = (int) *((unsigned long long *) entry_stacktop);
  char **argv = ((char **) entry_stacktop) + 1;

  Elf64_Ehdr *stub_ehdr = (Elf64_Ehdr *) KITESHIELD_STUB_BASE;
  Elf64_Off phoff = stub_ehdr->e_phoff;

  Elf64_Phdr *app_phdr = (Elf64_Phdr *) (KITESHIELD_STUB_BASE + phoff +
                                         sizeof(Elf64_Phdr));

  void *app_start = (void *) app_phdr->p_vaddr;
  void *entry;
  void *phdr_addr;
  void *interp_base;
  map_elf_from_mem(app_start, &entry, &phdr_addr, &interp_base);
  setup_auxv(argv, entry, phdr_addr, interp_base);
}
