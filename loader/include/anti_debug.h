#ifndef __KITESHIELD_ANTI_DEBUG_H
#define __KITESHIELD_ANTI_DEBUG_H

#include "loader/include/types.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"
#include "loader/include/debug.h"
#include "loader/include/string.h"
#include "loader/include/obfuscated_strings.h"

#define TRACED_MSG "We're being traced, exiting (-DNO_ANTIDEBUG to suppress)"

static const char *nextline(const char *curr_line)
{
  const char *ptr = curr_line;
  while (*ptr != '\0') {
    if (*ptr == '\n') return ptr + 1;
    ptr++;
  }

  return NULL; /* EOF */
}

/* Check the TracerPid field in /proc/<pid>/status to verify we're not being
 * ptraced.
 *
 * Always inline this function so that a reverse engineer doesn't have to
 * simply neuter a single function in the compiled code to defeat calls to it
 * everywhere. */
static inline int __attribute__((always_inline)) check_traced()
{
#ifdef NO_ANTIDEBUG
  return 0;
#endif

  /* Use /proc/<pid>/status instead of /proc/self/status to make this just a
   * bit more frusturating to circumvent as <pid> will change with each exec.
   *
   * PROC_DIR = "/proc/"
   * SLASH_STATUS = "/status"
   */
  char proc_path[128];
  strncpy(proc_path, DEOBF_STR(PROC_PATH), sizeof(proc_path));
  char pid_buf[32];
  pid_t pid = sys_getpid();
  itoa((unsigned long) pid, 0, pid_buf, sizeof(pid_t), 10);
  strncat(proc_path, pid_buf, sizeof(pid_buf));
  strncat(proc_path, DEOBF_STR(SLASH_STATUS), sizeof(proc_path) - sizeof(pid_buf));

  /* The check this function performs could be bypassed by running the process
   * in a mount namespace with /proc being something controlable from userspace
   * for instance, a bunch of regular files on an actual (non proc) filesystem.
   * Check we're actually reading from a procfs by stat'ing /proc/<pid>/status
   * and verifying that st_size is zero (which it should always be if /proc is
   * a real procfs. If a reverse engineer tries to create a fake proc with a
   * regular file for /proc/<pid>/status, st_size should be greater than 0. */
  struct stat stat;
  DIE_IF_FMT(sys_stat(proc_path, &stat) < 0, "could not stat %s", proc_path);
  if (stat.st_size != 0)
    return 1;

  int fd =  sys_open(proc_path, O_RDONLY, 0);
  DIE_IF_FMT(fd < 0, "could not open %s error %d", proc_path, fd);

  char buf[4096]; /* Should be enough to hold any /proc/<pid>/status */
  int ret = sys_read(fd, buf, sizeof(buf) - 1);
  DIE_IF_FMT(ret < 0, "read failed with error %d", ret);
  buf[ret] = '\0';
  sys_close(fd);

  const char *line = buf;
  char *tracerpid_field = DEOBF_STR(TRACERPID_PROC_FIELD); /* "TracerPid:" */
  do {
    if (strncmp(line, tracerpid_field, 10) != 0) continue;

    /* Strip spaces between : and the pid */
    const char *curr = line + 10;
    while (*curr != '\0') {
      if (*curr != ' ' && *curr != '\t') break;
      curr++;
    }

    if (curr[0] == '0' && curr[1] == '\n') return 0;
    else return 1;
  } while ((line = nextline(line)) != NULL);

  DEBUG(
      "Could not find TracerPid in /proc/self/status, assuming we're traced");
  return 1;
}

/* Delivers a SIGTRAP to ourself by executing an int3. This should be picked up
 * by the signal handler registered with signal_antidebug_init, which
 * increments the global sigtrap_counter by one. If we're running under gdb and
 * the reverse engineer has not explicitly configured GDB to pass the SIGTRAP
 * onto the debugged program, the signal handler won't be invoked, and thus the
 * global won't be incremented, telling us we're being debugged.
 *
 * Always inline antidebug_signal_check() for the same reasons as
 * check_traced() above. */
extern int sigtrap_counter;
static inline int __attribute__((always_inline)) antidebug_signal_check()
{
#ifdef NO_ANTIDEBUG
  return 0;
#endif

  int oldval = sigtrap_counter;
  asm volatile ("int3");

  return sigtrap_counter != oldval + 1;
}

/* Sets the maximum core dump size to 0 via setrlimit. When called in the child
 * (or in the parent pre-fork as limits are inherited after fork), this makes
 * it impossible to eg. hit the child with a SIGSEGV and get a core dump.
 *
 * Always inline antidebug_rlimit_set_zero_core for the same reasons as
 * check_traced() above.
 */
static inline void __attribute__((always_inline))
antidebug_rlimit_set_zero_core()
{
#ifdef NO_ANTIDEBUG
  return;
#endif

  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  int ret = sys_setrlimit(RLIMIT_CORE, &limit);
  DIE_IF_FMT(ret != 0, "rlimit(RLIMIT_CORE, {0, 0}) failed with %d", ret);
}

void signal_antidebug_init();
void antidebug_set_nondumpable();

#endif /* __KITESHIELD_ANTI_DEBUG_H */

