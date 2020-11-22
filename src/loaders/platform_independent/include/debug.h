#ifndef KITESHIELD_DEBUG_H_
#define KITESHIELD_DEBUG_H_

#include <stdarg.h>
#include "loaders/platform_independent/include/syscalls.h"

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
    exit(1);                                                                  \
  } while (0)
#else
#define DIE(msg)                                                              \
  do {                                                                        \
    if (cond) {                                                               \
      exit(0);                                                                \
    }                                                                         \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_FMT(msg, ...)                                                     \
  do {                                                                        \
    minimal_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);               \
    exit(1);                                                                  \
  } while (0)
#else
#define DIE_FMT(msg, ...)                                                     \
  do {                                                                        \
    exit(0);                                                                  \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF(cond, msg)                                                     \
  do {                                                                        \
    if (cond) {                                                               \
      minimal_printf(2, KITESHIELD_PREFIX msg "\n");                          \
      exit(1);                                                                \
    }                                                                         \
  } while (0)
#else
#define DIE_IF(cond, msg)                                                     \
  do {                                                                        \
    if (cond) {                                                               \
      exit(0);                                                                \
    }                                                                         \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF_FMT(cond, msg, ...)                                            \
  do {                                                                        \
    if (cond) {                                                               \
      minimal_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);             \
      exit(1);                                                                \
    }                                                                         \
  } while (0)
#else
#define DIE_IF_FMT(cond, msg, ...)                                            \
  do {                                                                        \
    if (cond) {                                                               \
      exit(0);                                                                \
    }                                                                         \
  } while (0)
#endif

void minimal_printf(int fd, const char *format, ...);

#endif
