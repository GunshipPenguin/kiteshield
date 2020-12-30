#include "loader/include/string.h"
#include "loader/include/types.h"

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
  static char *digits = "0123456789abcdef";
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

