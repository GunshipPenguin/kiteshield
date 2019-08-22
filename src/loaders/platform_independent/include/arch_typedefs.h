#ifndef KITESHIELD_LOADERS_PLATFORM_INDEPENDENT_INCLUDE_ARCH_TYPEDEFS_
#define KITESHIELD_LOADERS_PLATFORM_INDEPENDENT_INCLUDE_ARCH_TYPEDEFS_

#define NULL 0

#ifdef __amd64__
typedef unsigned long long size_t;
typedef signed long long ssize_t;
typedef unsigned long long off_t;
#else
#error "Architechure not supported"
#endif

#endif
