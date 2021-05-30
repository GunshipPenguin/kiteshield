/* Note most actual antidebug code is defined in this header file as it
 * has to be inlined everywhere. */
#include "loader/include/anti_debug.h"

int sigtrap_counter = 0;

void sigtrap_handler(int sig)
{
  DEBUG("caught SIGTRAP, incrementing SIGTRAP count (antidebug)");
  sigtrap_counter++;
}

/* Simple signal restorer that simply calls sigreturn(2). Normally this is
 * handled by glibc, but we need to explicitly declare and pass it in to
 * rt_sigaction(2) given our freestanding environment.
 */
void restorer();
asm ("restorer:\n"
     "  mov $15, %rax\n"
     "  syscall");

void antidebug_signal_init()
{
#ifdef NO_ANTIDEBUG
  return;
#endif

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

/* Sets the environment variables LD_PRELOAD, LD_AUDIT and LD_DEBUG (if
 * present) to empty strings.
 *
 * The first two of these can be used by a reverse engineer to run custom code
 * in dynamically linked packed program's context, the last can be set to to
 * provide potentially useful information on linker operations.
 */
void antidebug_remove_ld_env_vars(void *entry_stacktop)
{
#ifdef NO_ANTIDEBUG
  return;
#endif

  char **environ = entry_stacktop;

  /* Advance past argc */
  environ++;

  /* Advance past argv */
  while (*(++environ) != 0);
  environ++;

  for (char **v = environ; *v != NULL; v++) {
    if (strncmp(*v, DEOBF_STR(LD_PRELOAD), 9) == 0) {
      DEBUG_FMT("LD_PRELOAD is set to %s, removing", *v + 11);
      (*v)[11] = '\0';
    } else if (strncmp(*v, DEOBF_STR(LD_AUDIT), 7) == 0) {
      DEBUG_FMT("LD_AUDIT is set to %s, removing", *v + 9);
      (*v)[9] = '\0';
    } else if (strncmp(*v, DEOBF_STR(LD_DEBUG), 7) == 0) {
      DEBUG_FMT("LD_DEBUG is set to %s, removing", *v + 9);
      (*v)[9] = '\0';
    }
  }
}

