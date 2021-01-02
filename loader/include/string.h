#ifndef __KITESHIELD_STRING_H
#define __KITESHIELD_STRING_H

#include "loader/include/types.h"

size_t strnlen(
    const char *s,
    size_t maxlen);

void itoa(
    unsigned long val,
    int is_signed,
    char *buf,
    int bitwidth,
    int radix);

char *strncpy(
    char *dest,
    const char *src,
    size_t n);

char *strncat(
    char *dest,
    const char *src,
    size_t n);

int strncmp(
    const char *s1,
    const char *s2,
    size_t n);

#endif /* __KITESHIELD_STRING_H */
