#ifndef KITESHIELD_DEBUG_H_
#define KITESHIELD_DEBUG_H_

#include <stdarg.h>

#ifdef DEBUG_OUTPUT
#define DEBUG(fmtstr) minimal_printf(1, fmtstr "\n")
#else
#define DEBUG(fmtstr) ;
#endif

#ifdef DEBUG_OUTPUT
#define DEBUG_FMT(fmtstr, ...) minimal_printf(1, fmtstr "\n", __VA_ARGS__)
#else
#define DEBUG_FMT(fmtstr, ...) ;
#endif

void minimal_printf(int fd, const char *format, ...);

#endif
