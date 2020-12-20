#include "loader/include/syscalls.h"
#include "loader/include/types.h"

ssize_t sys_write(int fd, const char *s, size_t count)
{
  ssize_t ret = 0;

  asm("mov $1, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "=rm" (ret)
  :   "rm" (fd), "rm" (s), "rm" (count));

  return ret;
}

ssize_t sys_read(int fd, void *buf, size_t count)
{
  ssize_t ret = 0;

  asm("mov $0, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "=rm" (ret)
  :   "rm" (fd), "rm" (buf), "rm" (count));

  return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
  off_t ret = 0;

  asm("mov $8, %%rax\n"
      "mov %0, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov %2, %%edx\n"
      "syscall\n"
      "mov %%rax, %3"
  :   "=rm" (ret)
  :   "rm" (fd), "rm" (offset), "rm" (whence));

  return ret;
}

int sys_open(const char *pathname, int flags, int mode)
{
  int ret = 0;

  asm("mov $2, %%rax\n"
      "movq %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
      "syscall\n"
      "mov %%eax, %0"
  :   "+rm" (ret)
  :   "rm" (pathname), "rm" (flags), "rm" (mode));

  return ret;
}

int sys_close(int fd)
{
  int ret = 0;

  asm("mov $3, %%rax\n"
      "movq %1, %%rdi\n"
      "syscall\n"
      "mov %%eax, %0"
  :   "+rm" (ret)
  :   "rm" (fd));

  return ret;
}

void sys_exit(int status)
{
  asm("mov $60, %%rax\n"
      "mov %0, %%rdi\n"
      "syscall"
  :
  :   "rm" (status));
}

void *sys_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
  void *ret = NULL;

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

int sys_mprotect(void *addr, size_t len, int prot)
{
  int ret = 0;

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

long sys_ptrace(
    enum __ptrace_request request,
    pid_t pid,
    void *addr,
    void *data)
{
  long ret = 0;

  /* Note that the raw kernel-level ptrace interface differs from the one
   * exposed by glibc with regards to the PTRACE_PEEK requests. Glibc *returns*
   * the data, while the kernel-level interface stores it in *data.
   *
   * This function exposes the kernel-level interface.
   */
  asm("movq $101, %%rax\n"
      "movl %1, %%edi\n"
      "movq %2, %%rsi\n"
      "movq %3, %%rdx\n"
      "movq %4, %%r10\n"
      "syscall\n"
      "movq %%rax, %0\n"
  :   "+rm" (ret)
  :   "rm" (request), "rm" (pid), "rm" (addr), "rm" (data));

  return ret;
}

pid_t sys_wait4(int *wstatus)
{
  pid_t ret = 0;

  /* We pass NULL for the pid/options/rusage arguments to simpify the function
   * definition (we don't currently have a need for these arguments) */
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

pid_t sys_fork()
{
  pid_t ret = 0;

  asm("movq $57, %%rax\n"
      "syscall\n"
      "movl %%eax, %0\n"
  :   "+rm" (ret)
  :);

  return ret;
}

int sys_kill(pid_t pid, int sig)
{
  pid_t ret = 0;

  asm("movq $62, %%rax\n"
      "movl %1, %%edi\n"
      "movl %2, %%esi\n"
      "syscall\n"
      "movl %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (pid), "rm" (sig));

  return ret;
}

