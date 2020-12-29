#include "loader/include/anti_debug.h"

int sigtrap_counter = 0;
void restorer();

void sigtrap_handler(int sig)
{
  DEBUG("caught SIGTRAP, incrementing SIGTRAP count (antidebug)");
  sigtrap_counter++;
}

void signal_antidebug_init()
{
  struct kernel_sigaction sa;
  sa.sa_mask = ~0UL;
  sa.sa_handler = sigtrap_handler;
  sa.sa_flags = SA_RESTORER;
  sa.sa_restorer = &restorer;

  int res = sys_rt_sigaction(SIGTRAP, &sa, NULL);
  DIE_IF_FMT(res < 0, "rt_sigaction failed with errro %d", res);
}

void antidebug_set_nondumpable()
{
#ifdef NO_ANTIDEBUG
  return;
#endif

  int ret = sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  DIE_IF_FMT(ret != 0, "prctl(PR_SET_DUMPABLE, 0) failed with %d", ret);
}

