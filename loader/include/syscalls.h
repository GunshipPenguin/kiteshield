#ifndef __KITESHIELD_SYSCALLS_H
#define __KITESHIELD_SYSCALLS_H

/* System call constants/defines and wrapper function prototypes.
 *
 * All of the sys_* functions are very lightweight wrappers around the
 * kernel-level syscall interface. Importantly, they expose the *raw* kernel
 * interface, and thus differ from the wrappers in glibc (eg. open(2),
 * read(2)). Often the interface exposed by glibc is the same as the raw kernel
 * interface, but sometimes it differs (eg. ptrace). These functions have the
 * sys_* prefix to emphasize that fact.
 */

#include <stdint.h>
#include "loader/include/types.h"

/* mmap syscall constants/defines */
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0

/* open syscall constants/defines */
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02

/* lseek syscall constants/defines */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* ptrace syscall constants/defines */
enum __ptrace_request {
  PTRACE_TRACEME = 0,
  PTRACE_PEEKTEXT = 1,
  PTRACE_PEEKDATA = 2,
  PTRACE_PEEKUSER = 3,
  PTRACE_POKETEXT = 4,
  PTRACE_POKEDATA = 5,
  PTRACE_POKEUSER = 6,
  PTRACE_CONT = 7,
  PTRACE_KILL = 8,
  PTRACE_SINGLESTEP = 9,
  PTRACE_GETREGS = 12,
  PTRACE_SETREGS = 13,
  PTRACE_GETFPREGS = 14,
  PTRACE_SETFPREGS = 15,
  PTRACE_ATTACH = 16,
  PTRACE_DETACH = 17,
  PTRACE_GETFPXREGS = 18,
  PTRACE_SETFPXREGS = 19,
  PTRACE_SYSCALL = 24,
  PTRACE_GET_THREAD_AREA = 25,
  PTRACE_SET_THREAD_AREA = 26,
  PTRACE_ARCH_PRCTL = 30,
  PTRACE_SYSEMU = 31,
  PTRACE_SYSEMU_SINGLESTEP = 32,
  PTRACE_SINGLEBLOCK = 33,
  PTRACE_SETOPTIONS = 0x4200,
  PTRACE_GETEVENTMSG = 0x4201,
  PTRACE_GETSIGINFO = 0x4202,
  PTRACE_SETSIGINFO = 0x4203,
  PTRACE_GETREGSET = 0x4204,
  PTRACE_SETREGSET = 0x4205,
  PTRACE_SEIZE = 0x4206,
  PTRACE_INTERRUPT = 0x4207,
  PTRACE_LISTEN = 0x4208,
  PTRACE_PEEKSIGINFO = 0x4209,
  PTRACE_GETSIGMASK = 0x420a,
  PTRACE_SETSIGMASK = 0x420b,
  PTRACE_SECCOMP_GET_FILTER = 0x420c,
  PTRACE_SECCOMP_GET_METADATA = 0x420c
};

enum __ptrace_setoptions {
  PTRACE_O_TRACESYSGOOD = 0x00000001,
  PTRACE_O_TRACEFORK = 0x00000002,
  PTRACE_O_TRACEVFORK = 0x00000004,
  PTRACE_O_TRACECLONE = 0x00000008,
  PTRACE_O_TRACEEXEC = 0x00000010,
  PTRACE_O_TRACEVFORKDONE = 0x00000020,
  PTRACE_O_TRACEEXIT = 0x00000040,
  PTRACE_O_TRACESECCOMP = 0x00000080,
  PTRACE_O_EXITKILL = 0x00100000,
  PTRACE_O_SUSPEND_SECCOMP = 0x00200000,
  PTRACE_O_MASK  = 0x003000ff
};

enum __ptrace_eventcodes {
  PTRACE_EVENT_FORK = 1,
  PTRACE_EVENT_VFORK = 2,
  PTRACE_EVENT_CLONE = 3,
  PTRACE_EVENT_EXEC = 4,
  PTRACE_EVENT_VFORK_DONE = 5,
  PTRACE_EVENT_EXIT = 6,
  PTRACE_EVENT_SECCOMP  = 7,
  PTRACE_EVENT_STOP = 128
};

struct __ptrace_peeksiginfo_args {
  uint64_t off;
  uint32_t flags;
  int32_t nr;
};

enum __ptrace_peeksiginfo_flags {
  PTRACE_PEEKSIGINFO_SHARED = (1 << 0)
};

struct __ptrace_seccomp_metadata {
  uint64_t filter_off;
  uint64_t flags;
};

/* Defined in kernel headers, needed for PTRACE_GETREGS */
struct user_regs_struct {
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long bp;
  unsigned long bx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long ax;
  unsigned long cx;
  unsigned long dx;
  unsigned long si;
  unsigned long di;
  unsigned long orig_ax;
  unsigned long ip;
  unsigned long cs;
  unsigned long flags;
  unsigned long sp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long gs_base;
  unsigned long ds;
  unsigned long es;
  unsigned long fs;
  unsigned long gs;
};

/* wait4 syscall constants/defines */
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#define WTERMSIG(status) ((status) & 0x7f)
#define WSTOPSIG(status) WEXITSTATUS(status)
#define WIFEXITED(status) (WTERMSIG(status) == 0)
#define WIFSIGNALED(status) \
  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
#define WIFSTOPPED(status) (((status) & 0xff) == 0x7f)
#ifdef WCONTINUED
# define WIFCONTINUED(status) ((status) == W_CONTINUED)
#endif

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000

#define __WNOTHREAD	0x20000000
#define __WALL		0x40000000
#define __WCLONE	0x80000000

/* rt_sigaction syscall constants/defines */
struct kernel_sigaction {
  void (*sa_handler)(int);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  unsigned long sa_mask;
};

#define SA_NOCLDSTOP	0x00000001u
#define SA_NOCLDWAIT	0x00000002u
#define SA_SIGINFO	0x00000004u
#define SA_ONSTACK	0x08000000u
#define SA_RESTART	0x10000000u
#define SA_NODEFER	0x40000000u
#define SA_RESETHAND	0x80000000u

#define SA_NOMASK	SA_NODEFER
#define SA_ONESHOT	SA_RESETHAND

#define SA_RESTORER	0x04000000

/* prctl constants/defines */
#define PR_GET_DUMPABLE   3
#define PR_SET_DUMPABLE   4

/* stat constants/defines */
struct stat {
	unsigned long long	st_dev;
	unsigned char	__pad0[4];

	unsigned long	__st_ino;

	unsigned int	st_mode;
	unsigned int	st_nlink;

	unsigned long	st_uid;
	unsigned long	st_gid;

	unsigned long long	st_rdev;
	unsigned char	__pad3[4];

	long long	st_size;
	unsigned long	st_blksize;

	unsigned long long	st_blocks;

	unsigned long	st_atime;
	unsigned long	st_atime_nsec;

	unsigned long	st_mtime;
	unsigned int	st_mtime_nsec;

	unsigned long	st_ctime;
	unsigned long	st_ctime_nsec;

	unsigned long long	st_ino;
};

/* setrlimit constants/defines */
typedef unsigned long rlim_t;
struct rlimit {
  rlim_t rlim_cur;
  rlim_t rlim_max;
};

/* Kinds of resource limit.  */
enum rlimit_resource {
  RLIMIT_CPU = 0,
  RLIMIT_FSIZE = 1,
  RLIMIT_DATA = 2,
  RLIMIT_STACK = 3,
  RLIMIT_CORE = 4,
  RLIMIT_RSS = 5,
  RLIMIT_NOFILE = 7,
  RLIMIT_AS = 9,
  RLIMIT_NPROC = 6,
  RLIMIT_MEMLOCK = 8,
  RLIMIT_LOCKS = 10,
  RLIMIT_SIGPENDING = 11,
  RLIMIT_MSGQUEUE = 12,
  RLIMIT_NICE = 13,
  RLIMIT_RTPRIO = 14,
  RLIMIT_RTTIME = 15,
};

/* clone constants/defines */
#define CSIGNAL              0x000000ff
#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_PTRACE         0x00002000
#define CLONE_VFORK          0x00004000
#define CLONE_PARENT         0x00008000
#define CLONE_THREAD         0x00010000
#define CLONE_NEWNS          0x00020000
#define CLONE_SYSVSEM        0x00040000
#define CLONE_SETTLS         0x00080000
#define CLONE_PARENT_SETTID  0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED       0x00400000
#define CLONE_UNTRACED       0x00800000
#define CLONE_CHILD_SETTID   0x01000000
#define CLONE_NEWCGROUP      0x02000000
#define CLONE_NEWUTS         0x04000000
#define CLONE_NEWIPC         0x08000000
#define CLONE_NEWUSER        0x10000000
#define CLONE_NEWPID         0x20000000
#define CLONE_NEWNET         0x40000000
#define CLONE_IO             0x80000000

/* syscall wrapper prototypes */
ssize_t sys_write(
    int fd,
    const char *s,
    size_t count);

ssize_t sys_read(
    int fd,
    void *buf,
    size_t count);

off_t sys_lseek(
    int fd,
    off_t offset,
    int whence);

int sys_open(
    const char *pathname,
    int flags,
    int mode);

int sys_close(
    int fd);

void sys_exit(
    int status) __attribute__((noreturn));

void *sys_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int sys_mprotect(
    void *addr,
    size_t len,
    int prot);

long sys_ptrace(
    enum __ptrace_request,
    pid_t pid,
    void *addr,
    void *data);

pid_t sys_wait4(
    pid_t pid,
    int *wstatus,
    int options);

pid_t sys_fork();

int sys_kill(
    pid_t pid,
    int sig);

int sys_tgkill(
    pid_t tgid,
    pid_t tid,
    int sig);

pid_t sys_getpid();

int sys_rt_sigaction(
    int sig,
    const struct kernel_sigaction *act,
    const struct kernel_sigaction *oact);

int sys_prctl(
    int option,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5);

int sys_stat(
    const char *pathname,
    struct stat *statbuf);

int sys_setrlimit(
    int resource,
    struct rlimit *rlim);

#endif /* __KITESHIELD_SYSCALLS_H */

