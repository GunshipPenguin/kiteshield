#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

void *print_message_function(void *ptr)
{
  char *message = (char *) ptr;
  printf("%s\n", message);
}

int main()
{
  printf("about to fork\n");
  fflush(stdout);

  pid_t p = fork();
  if (p == 0) {
    pthread_t thread;
    char *message = "executing in new thread";
    int ret = pthread_create(
    &thread, NULL, print_message_function, (void *) message);

    pthread_join(thread, NULL);

    printf("thread returns: %d\n",ret);
  } else {
    int wstatus;
    wait(&wstatus);

    if (WIFEXITED(wstatus))
      printf("child exited with status %d\n", WEXITSTATUS(wstatus));
  }

  return 0;
}
