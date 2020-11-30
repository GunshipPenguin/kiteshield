#include "loader/include/arch_typedefs.h"

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
  int fd = -1;

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

void exit(int status) {
  /* sys_exit */
  asm("mov $60, %%rax\n"
      "mov %0, %%rdi\n"
      "syscall"
  :
  :   "rm" (status));
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  void *ret = (void *) -1;

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
  :   "rm" (addr), "rm" (length), "rm" (prot), "rm" (flags), "rm" (fd),
      "rm" (offset));

  return ret;
}

int mprotect(void *addr, size_t len, int prot) {
  int ret = -1;

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


