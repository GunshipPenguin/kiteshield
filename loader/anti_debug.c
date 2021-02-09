/* Note most actual antidebug code is defined in this header file as it
 * has to be inlined everywhere. */
#include "loader/include/anti_debug.h"

int sigtrap_counter = 0;
void restorer();

void sigtrap_handler(int sig)
{
  DEBUG("caught SIGTRAP, incrementing SIGTRAP count (antidebug)");
  sigtrap_counter++;
}

void antidebug_signal_init()
{
  struct kernel_sigaction sa;
  sa.sa_mask = ~0UL;
  sa.sa_handler = sigtrap_handler;
  sa.sa_flags = SA_RESTORER;
  sa.sa_restorer = &restorer;

  int res = sys_rt_sigaction(SIGTRAP, &sa, NULL);
  DIE_IF_FMT(res < 0, "rt_sigaction failed with errro %d", res);
}

/* Sets the process's dumpable flag to 0. This makes ptrace attaches impossible
 * and disables coredumping. We can only do this in the parent of course, since
 * the child needs to be ptraced by the process running the runtime.
 *
 * While the latter point above (disabling coredumping) is also achieved
 * through our use of rlimit to set the max core dump size to 0, this is still
 * one more thing a reverse engineer has to get around, which makes it a
 * positive.
 */
void antidebug_prctl_set_nondumpable()
{
#ifdef NO_ANTIDEBUG
  return;
#endif

  int ret = sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  DIE_IF_FMT(ret != 0, "prctl(PR_SET_DUMPABLE, 0) failed with %d", ret);
}

