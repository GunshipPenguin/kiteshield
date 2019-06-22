#include <elf.h>
#include "defs.h"
#include <stdarg.h>

#define NULL 0

#define STDOUT 1
#define STDERR 2

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

/* mmap syscall constants */
#define MAP_SHARED	0x01
#define MAP_PRIVATE	0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0

#define MAP_FAILED ((void *) -1)

/* open syscall constants */
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02

/* lseek syscall constants */
# define SEEK_SET 0
# define SEEK_CUR 1
# define SEEK_END 2

/* typedefs found in libc headers */
typedef unsigned long long size_t;
typedef signed long long ssize_t;
typedef unsigned long long off_t;

size_t strnlen(const char *s, size_t maxlen) {
  int len = 0;
  while (*(s + len) != '\0' && len <= maxlen) {
    len++;
  }

  return len;
}

ssize_t write(int fd, const char *s, size_t count) {
  ssize_t bytes_written;

  /* sys_write */
  asm("mov $1, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "=rm" (bytes_written)
  :   "rm" (fd), "rm" (s), "rm" (count));

  return bytes_written;
}

ssize_t read(int fd, void *buf, size_t count) {
  ssize_t bytes_read;

  /* sys_read */
  asm("mov $0, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "=rm" (bytes_read)
  :   "rm" (fd), "rm" (buf), "rm" (count));

  return bytes_read;
}

off_t lseek(int fd, off_t offset, int whence) {
  off_t ret_offset;

  /* sys_lseek */
  asm("mov $8, %%rax\n"
      "mov %0, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov %2, %%edx\n"
      "syscall\n"
      "mov %%rax, %3"
  :   "=rm" (ret_offset)
  :   "rm" (fd), "rm" (offset), "rm" (whence));

  return ret_offset;
}

int open(const char *pathname, int flags, int mode) {
  int fd;

  /* sys_open */
  asm("mov $2, %%rax\n"
      "movq %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
      "syscall\n"
      "mov %%eax, %0"
  :   "+rm" (fd)
  :   "rm" (pathname), "rm" (flags), "rm" (mode));

  return fd;
}

void itoa(unsigned long long val, int is_signed, char *buf, int bitwidth, int radix) {
  static char digits[] = "0123456789ABCDEF";
  char *buf_ptr = buf;

  /* Determine if negative */
  if (is_signed && ((1 << (bitwidth - 1)) & val)) {
    *(buf_ptr++) = '-';
    val = ~(val-1);
  }

  do {
    *(buf_ptr++) = digits[val % radix];
  } while ((val /= radix) > 0);
  *buf_ptr = '\0';

  // Buf is now correct, but reversed
  char *start_ptr = buf;
  char *end_ptr = buf_ptr-1; // Avoid the '\0'
  while (start_ptr < end_ptr) {
    char temp = *start_ptr;
    *(start_ptr++) = *end_ptr;
    *(end_ptr--) = temp;
  }
}

char *strncpy(char *dest, const char *src, size_t n) {
  size_t i;

  for (i = 0; i < n && src[i] != '\0'; i++) {
    dest[i] = src[i];
  }

  for ( ; i < n; i++) {
    dest[i] = '\0';
  }

  return dest;
}

void minimal_printf(int fd, const char *format, ...) {
  va_list vl;
  va_start(vl, format);

  char msg_buf[512];
  char *msg_ptr = msg_buf;
  for (const char *fmt_ptr=format; *fmt_ptr != '\0'; fmt_ptr++) {
    if (*fmt_ptr != '%') {
      *(msg_ptr++) = *fmt_ptr;
      continue;
    }

    char item_buf[64];
    switch (*(fmt_ptr + 1)) {
      case 'p': itoa((unsigned long long) va_arg(vl, void *), 0, item_buf, 64, 16);
        break;
      case 'd': itoa(va_arg(vl, int), 0, item_buf, 64, 10);
        break;
      case 's': strncpy(item_buf, va_arg(vl, char *), sizeof(item_buf));
        break;
    }
    strncpy(msg_ptr, item_buf, sizeof(item_buf));

    msg_ptr += strnlen(item_buf, sizeof(item_buf));
    fmt_ptr++; // Advance past format specifier
  }

  write(fd, msg_buf, strnlen(msg_buf, sizeof(msg_buf)));
  va_end(vl);
}

void exit(int status) {
  /* sys_exit */
  asm("mov $60, %%rax\n"
      "mov %0, %%rdi\n"
      "syscall"
  :
  :   "rm" (status));
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  void *ret;

  /* sys_mmap */
  asm("mov $9, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "mov %4, %%r10d\n"
      "mov %5, %%r8d\n"
      "mov %6, %%r9\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "+rm" (ret)
  :   "rm" (addr), "rm" (length), "rm" (prot), "rm" (flags), "rm" (fd), "rm" (offset));

  return ret;
}

int mprotect(void *addr, size_t len, int prot) {
  int ret;

  /* sys_mmap */
  asm("movq $10, %%rax\n"
      "movq %1, %%rdi\n"
      "movq %2, %%rsi\n"
      "movl %3, %%edx\n"
      "syscall\n"
      "movl %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (addr), "rm" (len), "rm" (prot));

  return ret;
}

void map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr) {
  void *addr = mmap((void *) KITESHIELD_APP_BASE + phdr.p_vaddr, phdr.p_memsz, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    minimal_printf(STDERR, "mmap failure\n");
  }

  minimal_printf(STDOUT, "mapping LOAD section from packed binary at 0x%p\n", addr);

  /* Copy section */
  char *curr_addr = addr;
  for (Elf64_Off f_off = (Elf64_Addr) phdr.p_offset; f_off < phdr.p_offset + phdr.p_filesz; f_off++) {
    *(curr_addr++) = *((char *) elf_start + f_off);
  }

  /* Set correct permissions (change from -W-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0)  |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);

  size_t memsz = (phdr.p_memsz & PAGE_MASK) + PAGE_SIZE;
  int res = mprotect(addr, memsz, prot);

  if (res < 0) {
    minimal_printf(STDERR, "mprotect error\n");
    exit(1);
  }
}

void map_load_section_from_fd(int fd, Elf64_Phdr phdr) {
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

  void *load_addr = (void *) (KITESHIELD_INTERP_BASE + (phdr.p_vaddr & PAGE_MASK));
  Elf64_Off load_off = phdr.p_offset & PAGE_MASK;

  void *addr = mmap(load_addr, phdr.p_memsz, prot, MAP_PRIVATE | MAP_FIXED, fd, load_off);
  if (addr == MAP_FAILED) {
    minimal_printf(STDERR, "mmap failure\n");
    exit(1);
  }

  minimal_printf(STDOUT, "mapped LOAD section from fd at %p\n", addr);
}

void map_interp(void *path) {
  minimal_printf(STDOUT, "mapping INTERP ELF at path %s\n", path);
  int interp_fd = open(path, O_RDONLY, 0);

  if (interp_fd < -1) {
    minimal_printf(STDERR, "open failure\n");
    exit(1);
  }

  Elf64_Ehdr ehdr;
  if (read(interp_fd, &ehdr, sizeof(ehdr)) < 0) {
    minimal_printf(STDERR, "read failure\n");
    exit(1);
  }

  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;
    if (lseek(interp_fd, ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) < 0) {
      minimal_printf(STDERR, "lseek failure\n");
      exit(1);
    }

    if (read(interp_fd, &curr_phdr, sizeof(curr_phdr)) < 0) {
      minimal_printf(STDERR, "read failure\n");
      exit(1);
    }

    if (curr_phdr.p_type == PT_LOAD) {
      minimal_printf(STDOUT, "About to map segment from fd with offset %p\n", curr_phdr.p_offset);
      map_load_section_from_fd(interp_fd, curr_phdr);
    }
  }
}

void map_elf_from_mem(void *elf_start) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  int i;
  for (i = 0; i < ehdr->e_phnum; i++) {
    switch (curr_phdr->p_type) {
      case PT_LOAD: map_load_section_from_mem(elf_start, *curr_phdr);
        break;
      case PT_INTERP: map_interp(elf_start + curr_phdr->p_offset);
        break;
    }
    curr_phdr++;
  }
}

void load() {
  Elf64_Ehdr *stub_ehdr = (Elf64_Ehdr *) KITESHIELD_STUB_BASE;
  Elf64_Off phoff = stub_ehdr->e_phoff;

  Elf64_Phdr *app_phdr = (Elf64_Phdr *) (KITESHIELD_STUB_BASE + phoff + sizeof(Elf64_Phdr));
  void *app_start = (void *) app_phdr->p_vaddr;

  map_elf_from_mem(app_start);

  exit(0);
}
