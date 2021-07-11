#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>

int main()
{
  int i;
  for (i = 0; i < 50; i++) {
    pid_t p = fork();

    if (p == 0) {
      printf("in child i=%d\n", i);
      fflush(stdout);
      exit(0);
    } else {
      int wstatus;
      wait(&wstatus);

      if (WIFEXITED(wstatus)) {
        printf("in parent, child exited with status %d\n", WEXITSTATUS(wstatus));
        fflush(stdout);
      } else {
        abort();
      }
    }
  }
}
