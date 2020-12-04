#include "loader/include/types.h"
#include "loader/include/syscall_defines.h"

ssize_t write(int fd, const char *s, size_t count) {
  ssize_t bytes_written;

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
  asm("mov $60, %%rax\n"
      "mov %0, %%rdi\n"
      "syscall"
  :
  :   "rm" (status));
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  void *ret = (void *) -1;

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

long ptrace(enum __ptrace_request request, pid_t pid, void *addr,
             void *data) {
  long ret = -1;

  asm("movq $101, %%rax\n"
      "movl %1, %%edi\n"
      "movq %2, %%rsi\n"
      "movl %3, %%edx\n"
      "movq %4, %%r10\n"
      "syscall\n"
      "movq %%rax, %0\n"
  :   "+rm" (ret)
  :   "rm" (request), "rm" (pid), "rm" (addr), "rm" (data));

  return ret;
}

pid_t wait(int *wstatus) {
  pid_t ret = -1;

  /* The glibc wait actually wraps the wait4 syscall, which takes 4 arguments
   * we pass in NULL/-1 as needed for those args to get the same behaviour
   * as the glibc wrapper */
  asm("movq $61, %%rax\n"
      "movq $-1, %%rdi\n"
      "movq %1, %%rsi\n"
      "movq $0, %%rdx\n"
      "movq $0, %%r10\n"
      "syscall\n"
      "movl %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (wstatus));

  return ret;
}

