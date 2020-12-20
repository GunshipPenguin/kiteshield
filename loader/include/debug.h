#ifndef __KITESHIELD_DEBUG_H
#define __KITESHIELD_DEBUG_H

#include <stdarg.h>
#include "loader/include/syscalls.h"

#define KITESHIELD_PREFIX "[kiteshield] "

#ifdef DEBUG_OUTPUT
#define DEBUG(fmtstr) minimal_printf(1, KITESHIELD_PREFIX fmtstr "\n")
#else
#define DEBUG(fmtstr) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DEBUG_FMT(fmtstr, ...)                                                \
  minimal_printf(1, KITESHIELD_PREFIX fmtstr "\n", __VA_ARGS__)
#else
#define DEBUG_FMT(fmtstr, ...) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE(msg)                                                              \
  do {                                                                        \
    minimal_printf(2, KITESHIELD_PREFIX msg "\n");                            \
    sys_exit(1);                                                              \
  } while (0)
#else
#define DIE(msg) sys_exit(0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_FMT(msg, ...)                                                     \
  do {                                                                        \
    minimal_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);               \
    sys_exit(1);                                                              \
  } while (0)
#else
#define DIE_FMT(msg, ...)                                                     \
  do {                                                                        \
    sys_exit(0);                                                              \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF(cond, msg)                                                     \
  do {                                                                        \
    if (cond) {                                                               \
      minimal_printf(2, KITESHIELD_PREFIX msg "\n");                          \
      sys_exit(1);                                                            \
    }                                                                         \
  } while (0)
#else
#define DIE_IF(cond, msg)                                                     \
  do {                                                                        \
    if (cond) {                                                               \
      sys_exit(0);                                                            \
    }                                                                         \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF_FMT(cond, msg, ...)                                            \
  do {                                                                        \
    if (cond) {                                                               \
      minimal_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);             \
      sys_exit(1);                                                            \
    }                                                                         \
  } while (0)
#else
#define DIE_IF_FMT(cond, msg, ...)                                            \
  do {                                                                        \
    if (cond) {                                                               \
      sys_exit(0);                                                            \
    }                                                                         \
  } while (0)
#endif

void minimal_printf(int fd, const char *format, ...);

#endif /* __KITESHIELD_DEBUG_H */
