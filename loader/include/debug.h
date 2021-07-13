#ifndef __KITESHIELD_DEBUG_H
#define __KITESHIELD_DEBUG_H

#include <stdarg.h>
#include "loader/include/syscalls.h"

#define KITESHIELD_PREFIX "[kiteshield] "

/* Yes this would likely be simpler if ks_printf implemented a width specifier,
 * but introducing all that extra complexity to it just for this one use
 * (printing keys) isn't really of any value. Better to just special case it
 * here.
 */
#define STRINGIFY_KEY(key) \
  ({ char buf[(sizeof((key)->bytes) * 2) + 1]; \
     char *buf_ptr = buf; \
     for (int i = 0; i < KEY_SIZE; i++) { \
       uint8_t byte = (key)->bytes[i]; \
       if ((byte & 0xF0) == 0) { \
         (*buf_ptr++) = '0'; \
         itoa((key)->bytes[i], 0, buf_ptr, 8, 16); \
         buf_ptr ++; \
       } else { \
         itoa((key)->bytes[i], 0, buf_ptr, 8, 16); \
         buf_ptr += 2; \
       } \
     }; \
     buf[sizeof((key)->bytes) * 2] = '\0'; \
     buf; }) \

#ifdef DEBUG_OUTPUT
#define DEBUG(fmtstr) ks_printf(1, KITESHIELD_PREFIX fmtstr "\n")
#else
#define DEBUG(fmtstr) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DEBUG_FMT(fmtstr, ...)                                                \
  ks_printf(1, KITESHIELD_PREFIX fmtstr "\n", __VA_ARGS__)
#else
#define DEBUG_FMT(fmtstr, ...) do {} while (0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE(msg)                                                              \
  do {                                                                        \
    ks_printf(2, KITESHIELD_PREFIX msg "\n");                            \
    sys_exit(1);                                                              \
  } while (0)
#else
#define DIE(msg) sys_exit(0)
#endif

#ifdef DEBUG_OUTPUT
#define DIE_FMT(msg, ...)                                                     \
  do {                                                                        \
    ks_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);               \
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
      ks_printf(2, KITESHIELD_PREFIX msg "\n");                          \
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
      ks_printf(2, KITESHIELD_PREFIX msg "\n", __VA_ARGS__);             \
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

void ks_printf(int fd, const char *format, ...);

#endif /* __KITESHIELD_DEBUG_H */
