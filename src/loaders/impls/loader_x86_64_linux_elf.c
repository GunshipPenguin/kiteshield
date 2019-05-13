#include <elf.h>
#include "defs.h"
#include <stdarg.h>

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

/* typedefs found in libc headers */
typedef unsigned long long size_t;
typedef unsigned long long off_t;

size_t strnlen(const char *s, size_t maxlen) {
  int len = 0;
  while (*(s + len) != '\0' && len <= maxlen) {
    len++;
  }

  return len;
}

void write(int fd, const char *s, size_t count) {
  /* sys_write */
  asm("mov $1, %%rax\n"
      "mov $1, %%rdi\n"
      "mov %0, %%rsi\n"
      "mov %1, %%edx\n"
      "syscall"
  :
  :   "rm" (s), "rm" (count));
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

    char item_buf[32];
    switch (*(fmt_ptr + 1)) {
      case 'p': itoa((unsigned long long) va_arg(vl, void *), 0, item_buf, 64, 16);
        break;
      case 'd': itoa(va_arg(vl, int), 0, item_buf, 64, 10);
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
  asm("movq $9, %%rax\n"
      "movq %1, %%rdi\n"
      "movq %2, %%rsi\n"
      "movq %3, %%rdx\n"
      "movq %4, %%r10\n"
      "movq %5, %%r8\n"
      "movq %6, %%r9\n"
      "syscall\n"
      "movq %%rax, %0"
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

void map_load_section(void *elf_start, Elf64_Phdr phdr) {
  minimal_printf(STDERR, "mapping section at 0x%p\n", KITESHIELD_APP_BASE + phdr.p_vaddr);

  void *addr = mmap((void *) KITESHIELD_APP_BASE + phdr.p_vaddr, phdr.p_memsz, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (addr < 0) {
    minimal_printf(STDERR, "mmap failure");
    exit(1);
  }

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

void map_elf(void *elf_start) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  int i;
  for (i = 0; i < ehdr->e_phnum; i++) {
    switch (curr_phdr->p_type) {
      case PT_LOAD: map_load_section(elf_start, *curr_phdr);
        break;
      case PT_INTERP:
        /* TODO: Fill in this logic */
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

  map_elf(app_start);

  exit(0);
}
