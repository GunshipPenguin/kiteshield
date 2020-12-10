#include "common/include/defs.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"

struct byte_sub_info bs_info __attribute__((section(".bs_info")));

void handle_trap(pid_t pid, int wstatus)
{
  long res;
  struct user_regs_struct regs;

  res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);
  DIE_IF_FMT(WSTOPSIG(wstatus) != SIGTRAP,
             "child was stopped by signal %u at pc = %p, exiting",
             WSTOPSIG(wstatus), regs.ip);

  DEBUG_FMT("child hit instrumentation point at %p", regs.ip - 1);

  regs.ip--;
  res = sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  long word;
  res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.ip, &word);
  DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

  struct byte_sub *bs;
  int i = 0;
  for (; i < bs_info.num; i++) {
    if (bs_info.subs[i].addr == (void *) regs.ip) {
      bs = &bs_info.subs[i];
      break;
    }
  }

  DIE_IF_FMT(i == bs_info.num,
             "could not find byte sub at %p, exiting", regs.ip);

  DEBUG_FMT("function starting %p and ending %p", bs->func_start, bs->func_end);
  DEBUG_FMT("substituting byte %hhx at address %p", bs->value, regs.ip);
  word &= (~0) << 8;
  word |= bs->value;

  res = sys_ptrace(PTRACE_POKETEXT, pid, (void *) regs.ip, (void *) word);
  DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);

  res = sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
}

void runtime_start()
{
  DEBUG("starting ptrace runtime");
  DEBUG_FMT("number of bs_info entries: %u", bs_info.num);

#ifdef DEBUG_OUTPUT
  for (int i = 0; i < bs_info.num; i++) {
    struct byte_sub bs = bs_info.subs[i];
    DEBUG_FMT(
        "bs_info entry %u: value = %hhx, addr = %p",
        i, bs.value, bs.addr);
  }
#endif

  while (1) {
    int wstatus;
    pid_t pid = sys_wait4(&wstatus);
    DIE_IF(pid == -1, "wait4 syscall failed");

    if (WIFEXITED(wstatus)) {
      DEBUG_FMT("child exited with status %u", WEXITSTATUS(wstatus));
      return;
    }

    if (!WIFSTOPPED(wstatus)) {
      DEBUG("child was stopped unexpectedly, exiting");
      return;
    }

    handle_trap(pid, wstatus);
  }
}

/* Called into by the child to setup ptrace just before handing off control
 * to the packed binary */
long child_setup_ptrace()
{
  long ret = sys_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF(ret == -1, "child: sys_ptrace(PTRACE_TRACEME) failed");

  DEBUG("child: sys_ptrace(PTRACE_TRACEME) was successful");
  DEBUG("child: handing control to packed binary");
  return ret;
}

