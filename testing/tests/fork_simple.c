#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>

int main()
{
  pid_t p = fork();

  if (p == 0) {
    printf("in child\n");
  } else {
    int wstatus;
    wait(&wstatus);

    if (WIFEXITED(wstatus)) {
      printf("in parent, child exited with status %d\n", WEXITSTATUS(wstatus));
    }
  }

  return 0;
}
