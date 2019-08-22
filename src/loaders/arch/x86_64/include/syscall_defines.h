#ifndef KITESHIELD_LOADERS_ARCH_X86_64_INCLUDE_SYSCALL_DEFINES_H_ 
#define KITESHIELD_LOADERS_ARCH_X86_64_INCLUDE_SYSCALL_DEFINES_H_

/* mmap syscall constants */
#define MAP_SHARED	0x01
#define MAP_PRIVATE	0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0

#define MAP_FAILED ((void *) -1)

/* open syscall constants */
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02

/* lseek syscall constants */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#endif
