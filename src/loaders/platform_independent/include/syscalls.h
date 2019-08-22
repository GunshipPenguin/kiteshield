#ifndef KITESHIELD_LOADERS_PLATFORM_INDEPENDENT_SYSCALLS_H_
#define KITESHIELD_LOADERS_PLATFORM_INDEPENDENT_SYSCALLS_H_

ssize_t write(int fd, const char *s, size_t count);
ssize_t read(int fd, void *buf, size_t count); 
off_t lseek(int fd, off_t offset, int whence);
int open(const char *pathname, int flags, int mode);
void exit(int status);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int mprotect(void *addr, size_t len, int prot);

#endif