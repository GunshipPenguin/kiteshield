#include "loaders/platform_independent/include/arch_typedefs.h"
#include "loaders/platform_independent/include/debug.h"

ssize_t write(int fd, const char *s, size_t count);

static char *strncpy(char *dest, const char *src, size_t n) {
  size_t i;

  for (i = 0; i < n && src[i] != '\0'; i++) {
    dest[i] = src[i];
  }

  for ( ; i < n; i++) {
    dest[i] = '\0';
  }

  return dest;
}

void itoa(unsigned long long val, int is_signed, char *buf, int bitwidth, int radix) {
  char *digits = "0123456789abcdef";
  char *buf_ptr = buf;

  /* Determine if negative */
  if (is_signed && ((1 << (bitwidth - 1)) & val)) {
    *(buf_ptr++) = '-';
    val = ~(val-1);
  }

  do {
    *(buf_ptr++) = digits[val % radix];
  } while ((val /= radix) > 0);

  *buf_ptr = '\0';
  // Buf is now correct, but reversed
  char *start_ptr = buf;
  char *end_ptr = buf_ptr-1; // Avoid the '\0'
  while (start_ptr < end_ptr) {
    char temp = *start_ptr;
    *(start_ptr++) = *end_ptr;
    *(end_ptr--) = temp;
  }
}

size_t strnlen(const char *s, size_t maxlen) {
  int len = 0;
  while (*(s + len) != '\0' && len <= maxlen) {
    len++;
  }

  return len;
}

/**
 * Minimal version of printf offering the following format specifiers
 *
 * %p - Unsigned 64 bit hexadecimal integer (x64 pointer)
 * %l - Unsigned 64 bit decimal integer
 * %d - Signed 32 bit decimal integer
 * %s - Null terminated ASCII string
 */
void minimal_printf(int fd, const char *format, ...) {
  va_list vl;
  va_start(vl, format);

  char msg_buf[512];
  char *msg_ptr = msg_buf;
  for (const char *fmt_ptr=format; *fmt_ptr != '\0'; fmt_ptr++) {
    if (*fmt_ptr != '%') {
      *(msg_ptr++) = *fmt_ptr;
      continue;
    }

    char item_buf[64];
    switch (*(fmt_ptr + 1)) {
      case 'p': itoa((unsigned long long) va_arg(vl, void *), 0, item_buf, 64, 16);
        break;
      case 'l': itoa((unsigned long long) va_arg(vl, unsigned long long), 0, item_buf, 64, 10);
        break;
      case 'd': itoa(va_arg(vl, int), 1, item_buf, 32, 10);
        break;
      case 's': strncpy(item_buf, va_arg(vl, char *), sizeof(item_buf));
        break;
    }
    strncpy(msg_ptr, item_buf, sizeof(item_buf));

    msg_ptr += strnlen(item_buf, sizeof(item_buf));
    fmt_ptr++; // Advance past format specifier
  }

  write(fd, msg_buf, strnlen(msg_buf, sizeof(msg_buf)));
  va_end(vl);
}


