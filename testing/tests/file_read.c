#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
  char buf[5];
  int fd = open("/dev/urandom", 0);
  ssize_t nbytes = read(fd, buf, 5);
  printf("Read %d bytes from /dev/urandom\n", nbytes);

  return 0;
}

