#include "loader/include/syscall_defines.h"
#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"

void runtime_start() {
  while (1) {
    int wstatus;
    pid_t ret = wait(&wstatus);

    DIE_IF(ret == -1, "wait syscall failed");

    if (WIFSTOPPED(wstatus)) {
      DEBUG_FMT("child was stopped by signal %d", WSTOPSIG(wstatus));
    }

    return;
  }
}

/* Called into by the child to setup ptrace just before handing off control
 * to the packed binary */
long child_setup_ptrace() {
  long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF(ret == -1, "child -- ptrace(PTRACE_TRACEME) failed");

  DEBUG("child: ptrace(PTRACE_TRACEME) was successful");
  DEBUG("child: ready to hand control to packed binary");
  return ret;
}

