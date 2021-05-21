#include "loader/include/syscalls.h"
#include "loader/include/types.h"

ssize_t sys_write(int fd, const char *s, size_t count)
{
  ssize_t ret = 0;

  asm("mov $1, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
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
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
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
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%rax, %0"
  :   "=rm" (ret)
  :   "rm" (fd), "rm" (offset), "rm" (whence));

  return ret;
}

int sys_open(const char *pathname, int flags, int mode)
{
  int ret = 0;

  asm("mov $2, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%esi\n"
      "mov %3, %%edx\n"
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
      "mov %1, %%edi\n"
      "syscall\n"
      "mov %%eax, %0"
  :   "+rm" (ret)
  :   "rm" (fd));

  return ret;
}

void sys_exit(int status)
{
  asm("mov $60, %%rax\n"
      "mov %0, %%edi\n"
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

  asm("mov $10, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%edx\n"
      "syscall\n"
      "mov %%eax, %0\n"
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
  asm("mov $101, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%esi\n"
      "mov %3, %%rdx\n"
      "mov %4, %%r10\n"
      "syscall\n"
      "mov %%rax, %0\n"
  :   "+rm" (ret)
  :   "rm" (request), "rm" (pid), "rm" (addr), "rm" (data));

  return ret;
}

pid_t sys_wait4(int *wstatus)
{
  pid_t ret = 0;

  /* We pass NULL for the pid/options/rusage arguments to simpify the function
   * definition (we don't currently have a need for these arguments) */
  asm("mov $61, %%rax\n"
      "mov $-1, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov $0, %%rdx\n"
      "mov $0, %%r10\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (wstatus));

  return ret;
}

pid_t sys_fork()
{
  pid_t ret = 0;

  asm("mov $57, %%rax\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :);

  return ret;
}

int sys_kill(pid_t pid, int sig)
{
  pid_t ret = 0;

  asm("mov $62, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%esi\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (pid), "rm" (sig));

  return ret;
}

pid_t sys_getpid()
{
  pid_t ret = 0;

  asm("mov $39, %%rax\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :);

  return ret;
}

int sys_rt_sigaction(
    int sig,
    const struct kernel_sigaction *act,
    const struct kernel_sigaction *oact)
{
  int ret = 0;
  size_t sigsetsize = sizeof(act->sa_mask);

  asm("mov $13, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
      "mov %4, %%r10\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (sig), "rm" (act), "rm" (oact), "rm" (sigsetsize));

  return ret;
}

int sys_prctl(
    int option,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5)
{
  int ret = 0;

  asm("mov $157, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "mov %3, %%rdx\n"
      "mov %4, %%r10\n"
      "mov %5, %%r8\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (option), "rm" (arg2), "rm" (arg3), "rm" (arg4), "rm" (arg5));

  return ret;
}

int sys_stat(const char *pathname, struct stat *statbuf)
{
  int ret = 0;

  asm("mov $4, %%rax\n"
      "mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (pathname), "rm" (statbuf));

  return ret;
}

int sys_setrlimit(int resource, struct rlimit *rlim)
{
  int ret = 0;

  asm("mov $160, %%rax\n"
      "mov %1, %%edi\n"
      "mov %2, %%rsi\n"
      "syscall\n"
      "mov %%eax, %0\n"
  :   "+rm" (ret)
  :   "rm" (resource), "rm" (rlim));

  return ret;
}

