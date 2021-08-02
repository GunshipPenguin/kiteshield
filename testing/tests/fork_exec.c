#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main()
{
  pid_t pid = fork();

  if (pid == 0) {
    char *args[] = { "/bin/echo", "hello world", NULL };
    execv(args[0], args);
  } else {
    int wstatus;
    pid_t pid = wait(&wstatus);
    printf("child exited with status %d\n", WEXITSTATUS(wstatus));
    return 0;
  }
}
