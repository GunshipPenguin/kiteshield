#include <stdarg.h>

#include "loader/include/string.h"
#include "loader/include/types.h"
#include "loader/include/obfuscated_strings.h"
#include "loader/include/debug.h"

#define BITS(type) (sizeof(type) * 8)

/**
 * Minimalistic implementation of vsnprintf
 *
 * Format specifier prototype: %[length]specifier
 *
 * - Length sub-specifiers (optional):
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
void ks_vsnprintf(char *str, size_t size, const char *format, va_list vl)
{
  size_t curr_size = 0;
  char *msg_ptr = str;
  memset(str, 0, size);

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
      itoa((unsigned long) va_arg(vl, void *), 0, item_buf, BITS(void *), 16);
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
      length = BITS(long);
      item = va_arg(vl, long);
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
    default:
      DIE_FMT("Invalid format specifier in printf format string: %s", format);
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

copy: ;
    size_t item_size = strnlen(item_buf, sizeof(item_buf));
    if (curr_size + item_size >= size)
      return;

    strncpy(msg_ptr, item_buf, sizeof(item_buf));
    msg_ptr += item_size;
  }
}

void ks_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list vl;

  va_start(vl, format);
  ks_vsnprintf(str, size, format, vl);
  va_end(vl);
}

void ks_printf(int fd, const char *format, ...)
{
  va_list vl;
  char buf[4096];

  va_start(vl, format);
  ks_vsnprintf(buf, sizeof(buf), format, vl);
  sys_write(fd, buf, strnlen(buf, sizeof(buf)));
  va_end(vl);
}

int strncmp(const char *s1, const char *s2, size_t n)
{
  for (int i = 0; i < n; i++) {
    if (s1[i] != s2[i]) {
      return 1;
    }
  }

  return 0;
}

char *strncat(char *dest, const char *src, size_t n)
{
  char *end = dest;
  while (*end != '\0')
    end++;

  size_t i;
  for (i = 0; i < n; i++)
    end[i] = src[i];

  end[i] = '\0';
  return dest;
}

char *strncpy(char *dest, const char *src, size_t n)
{
  size_t i;
  for (i = 0; i < n && src[i] != '\0'; i++) {
    dest[i] = src[i];
  }

  for ( ; i < n; i++) {
    dest[i] = '\0';
  }

  return dest;
}

void itoa(
    unsigned long val,
    int is_signed,
    char *buf,
    int bitwidth,
    int radix)
{
  char *digits = DEOBF_STR(HEX_DIGITS);
  char *buf_ptr = buf;

  int negative = is_signed && ((1 << (bitwidth - 1)) & val);
  if (negative)
    val = ~(val-1);

  do {
    *(buf_ptr++) = digits[val % radix];
  } while ((val /= radix) > 0);

  if (negative)
    *(buf_ptr++) = '-';

  *buf_ptr = '\0';

  /* Buf is now correct, but reversed */
  char *start_ptr = buf;
  char *end_ptr = buf_ptr - 1; /* Avoid the '\0' */
  while (start_ptr < end_ptr) {
    char temp = *start_ptr;
    *(start_ptr++) = *end_ptr;
    *(end_ptr--) = temp;
  }
}

size_t strnlen(const char *s, size_t maxlen)
{
  int len = 0;
  while (*(s + len) != '\0' && len <= maxlen) {
    len++;
  }

  return len;
}

void *memcpy(void *dest, const void *src, size_t n)
{
  for (size_t i = 0; i < n; i++)
    ((char *) dest)[i] = ((char *) src)[i];

  return dest;
}

void *memset(void *s, int c, size_t n)
{
  for (size_t i = 0; i < n; i++)
    ((char *) s)[i] = (char) c;

  return s;
}
