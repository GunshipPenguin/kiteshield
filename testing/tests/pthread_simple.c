#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *print_message_function(void *ptr)
{
  char *message = (char *) ptr;
  printf("%s\n", message);
}

int main()
{
  pthread_t thread;
  char *message = "executing in new thread";
  int ret = pthread_create(
  &thread, NULL, print_message_function, (void *) message);

  pthread_join(thread, NULL);

  printf("thread returns: %d\n",ret);

  return 0;
}
