#include "common/include/defs.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"

struct trap_point_info tp_info __attribute__((section(".tp_info")));

struct trap_point *get_tp(void *addr) {
  struct trap_point *tp;
  int i = 0;
  for (; i < tp_info.num; i++) {
    if (tp_info.arr[i].addr == addr) {
      tp = &tp_info.arr[i];
      break;
    }
  }

  DIE_IF_FMT(i == tp_info.num,
             "could not find trap point at %p, exiting", addr);
  return tp;
}

void set_byte_at_addr(pid_t pid, void *addr, uint8_t value)
{
  long word;
  long res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, &word);
  DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

  word &= (~0) << 8;
  word |= value;

  res = sys_ptrace(PTRACE_POKETEXT, pid, addr, (void *) word);
  DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);
}

void single_step(pid_t pid)
{
  long res = sys_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_SINGLESTEP failed with error %d", res);
  int wstatus;
  sys_wait4(&wstatus);

  DIE_IF_FMT(WIFEXITED(wstatus),
             "child exited with status %u during single step",
             WEXITSTATUS(wstatus));
  DIE_IF(!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP,
         "child was stopped unexpectedly during single step, exiting");
}

void handle_trap(pid_t pid, int wstatus)
{
  long res;
  struct user_regs_struct regs;

  res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);
  DIE_IF_FMT(WSTOPSIG(wstatus) != SIGTRAP,
             "child was stopped by signal %u at pc = %p, exiting",
             WSTOPSIG(wstatus), regs.ip);

  DEBUG_FMT("child trapped at %p", regs.ip - 1);

  /* Back up the instruction pointer, replace the int3 byte with the original
   * program code, single step through the original instruction and replace
   * the int3 */
  regs.ip--;
  res = sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  struct trap_point *tp = get_tp((void *) regs.ip);
  set_byte_at_addr(pid, (void *) regs.ip, tp->value);

  single_step(pid);

  set_byte_at_addr(pid, (void *) regs.ip, 0xCC);

  res = sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
}

void runtime_start()
{
  DEBUG("starting ptrace runtime");
  DEBUG_FMT("number of tp_info entries: %u", tp_info.num);

#ifdef DEBUG_OUTPUT
  for (int i = 0; i < tp_info.num; i++) {
    struct trap_point tp = tp_info.arr[i];
    DEBUG_FMT(
        "tp_info entry %u: value = %hhx, addr = %p",
        i, tp.value, tp.addr);
  }
#endif

  while (1) {
    int wstatus;
    pid_t pid = sys_wait4(&wstatus);

    DIE_IF(pid == -1, "wait4 syscall failed");
    DIE_IF_FMT(WIFEXITED(wstatus),
               "child exited with status %u", WEXITSTATUS(wstatus));
    DIE_IF(!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP,
           "child was stopped unexpectedly, exiting");

    handle_trap(pid, wstatus);
  }
}

/* Called into by the child to setup ptrace just before handing off control
 * to the packed binary */
long child_setup_ptrace()
{
  long ret = sys_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF(ret == -1, "child: sys_ptrace(PTRACE_TRACEME) failed");

  DEBUG("child: PTRACE_TRACEME was successful");
  DEBUG("child: handing control to packed binary");
  return ret;
}

