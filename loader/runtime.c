#include "common/include/defs.h"

#include "loader/include/syscall_defines.h"
#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"

struct byte_sub_info bs_info __attribute__((section(".bs_info")));

void runtime_start()
{
  DEBUG("starting ptrace runtime");
  DEBUG_FMT("number of bs_info entries: %u", bs_info.num);

#ifdef DEBUG_OUTPUT
  for (int i = 0; i < bs_info.num; i++) {
    struct byte_sub bs = bs_info.subs[i];
    DEBUG_FMT("bs_info entry %u: value = %hhx, addr = %p", i, bs.value, bs.addr);
  }
#endif

  while (1) {
    int wstatus;
    long res;
    struct user_regs_struct regs;
    pid_t pid = wait(&wstatus);
    DIE_IF(pid == -1, "wait syscall failed");

    if (WIFEXITED(wstatus)) {
      DEBUG_FMT("child exited with status %u", WEXITSTATUS(wstatus));
      return;
    }

    if (!WIFSTOPPED(wstatus)) {
      DEBUG("child was stopped unexpectedly, exiting");
      return;
    }

    res = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);

    if (WSTOPSIG(wstatus) != SIGTRAP) {
      DEBUG_FMT("child was stopped by signal %u at pc = %p, exiting", WSTOPSIG(wstatus), regs.ip);
      return;
    }

    DEBUG_FMT("child hit instrumentation point at %p", regs.ip - 1);

    regs.ip--;
    res = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

    long word;
    res = ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.ip, &word);
    DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

    uint8_t sub_value;
    int i = 0;
    for (; i < bs_info.num; i++) {
      if (bs_info.subs[i].addr == (void *) regs.ip) {
        sub_value = bs_info.subs[i].value;
        break;
      }
    }

    if (i == bs_info.num) {
      DEBUG("could not find byte sub, exiting");
      return;
    }

    DEBUG_FMT("substituting byte %hhx at address %p", sub_value, regs.ip);
    word &= (~0) << 8;
    word |= sub_value;

    res = ptrace(PTRACE_POKETEXT, pid, (void *) regs.ip, (void *) word);
    DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);

    res = ptrace(PTRACE_CONT, pid, NULL, NULL);
    DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
  }
}

/* Called into by the child to setup ptrace just before handing off control
 * to the packed binary */
long child_setup_ptrace()
{
  long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF(ret == -1, "child: ptrace(PTRACE_TRACEME) failed");

  DEBUG("child: ptrace(PTRACE_TRACEME) was successful");
  DEBUG("child: handing control to packed binary");
  return ret;
}

