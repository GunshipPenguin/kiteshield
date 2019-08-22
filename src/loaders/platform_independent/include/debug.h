#ifndef KITESHIELD_DEBUG_H_
#define KITESHIELD_DEBUG_H_

#include <stdarg.h>

#ifdef DEBUG_OUTPUT
#define DEBUG(fmtstr) minimal_printf(1, fmtstr "\n")
#else
#define DEBUG(fmtstr) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DEBUG_FMT(fmtstr, ...) minimal_printf(1, fmtstr "\n", __VA_ARGS__)
#else
#define DEBUG_FMT(fmtstr, ...) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF(cond, msg) \
  do { \
    if (cond) { \
      minimal_printf(2, msg); \
      exit(1); \
    } \
  } while (0)
#else
#define DIE_IF(cond, msg) \
  do { \
    if (cond) { \
      exit(0); \
    } \
  } while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_IF_FMT(cond, msg, ...) \
  do { \
    if (cond) { \
      minimal_printf(2, msg, __VA_ARGS__); \
      exit(1); \
    } \
  } while (0)
#else
#define DIE_IF_FMT(cond, msg, ...) \
  do { \
    if (cond) { \
      exit(0); \
    } \
  } while (0)
#endif

void minimal_printf(int fd, const char *format, ...);

#endif
