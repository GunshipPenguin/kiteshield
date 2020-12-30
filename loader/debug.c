#ifdef DEBUG_OUTPUT

#include "loader/include/types.h"
#include "loader/include/syscalls.h"
#include "loader/include/debug.h"
#include "loader/include/string.h"

#define BITS(type) (sizeof(type) * 8)

/**
 * Minimalistic implementation of printf:
 *
 * Format specifier prototype: %[length]specifier
 *
 * - Length sub-specifiers (optional):
 *   - ll -- long long
 *   - l  -- long
 *   - hh -- char
 *
 * - Specifiers and default lengths (ie. with no length sub-specifier):
 *   - %p -- pointer                      -- sizeof(void *)
 *   - %d -- signed decimal integer       -- sizeof(int)
 *   - %u -- unsigned decimal integer     -- sizeof(int)
 *   - %x -- unsigned hexadecimal integer -- sizeof(int)
 *   - %s -- null-terminated string
 */
void minimal_printf(int fd, const char *format, ...)
{
  va_list vl;
  va_start(vl, format);

  char msg_buf[1024];
  __builtin_memset(msg_buf, 0, sizeof(msg_buf));
  char *msg_ptr = msg_buf;

  for (const char *fmt_ptr=format; *fmt_ptr != '\0'; fmt_ptr++) {
    if (*fmt_ptr != '%') {
      *(msg_ptr++) = *fmt_ptr;
      continue;
    }

    int length;
    unsigned long long item;
    char item_buf[128];
    __builtin_memset(item_buf, 0, sizeof(item_buf));

    fmt_ptr++;
    switch (*(fmt_ptr)) {
    /* Deal with the non length specifier case */
    case 'p':
      itoa((unsigned long long) va_arg(vl, void *), 0, item_buf, BITS(void *), 16);
      goto copy;
    case 'd':
      itoa(va_arg(vl, int), 1, item_buf, BITS(int), 10);
      goto copy;
    case 'u':
      itoa((unsigned int) va_arg(vl, unsigned int), 1, item_buf, BITS(unsigned int), 10);
      goto copy;
    case 'x':
      itoa((unsigned int) va_arg(vl, unsigned int), 1, item_buf, BITS(unsigned int), 16);
      goto copy;
    case 's':
      strncpy(item_buf, va_arg(vl, char *), sizeof(item_buf));
      goto copy;

    /* Length specifier given */
    case 'l':
      fmt_ptr++;
      if (*(fmt_ptr) == 'l') {
        length = BITS(long long);
        item = va_arg(vl, long long);
      } else {
        length = BITS(int);
        item = va_arg(vl, int);
      }
      break;
    case 'h':
      fmt_ptr++;
      if (*(fmt_ptr) == 'h') {
        length = BITS(unsigned char);
        /* Unsigned char gets promoted to int here, so take bottom 8 bits */
        item = va_arg(vl, int) & 0xFF;
      } else {
        DIE_FMT("Invalid length specifier in printf format string: %s", format);
      }
      break;
    }

    fmt_ptr++;
    switch (*(fmt_ptr)) {
    case 'd':
      itoa(item, 1, item_buf, length, 10);
      break;
    case 'u':
      itoa(item, 0, item_buf, length, 10);
      break;
    case 'x':
      itoa(item, 0, item_buf, length, 16);
      break;
    default:
      DIE_FMT("Invalid format specifier in printf format string: %s", format);
    }

copy:
    strncpy(msg_ptr, item_buf, sizeof(item_buf));
    msg_ptr += strnlen(item_buf, sizeof(item_buf));
  }

  sys_write(fd, msg_buf, strnlen(msg_buf, sizeof(msg_buf)));
  va_end(vl);
}

#endif /* DEBUG_OUTPUT */

