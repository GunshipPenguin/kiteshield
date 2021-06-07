#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *print_message_function(void *ptr)
{
  long id = (long) ptr;
  printf("Thread %d executing\n", id);
}

int main()
{
  long i;
  for (i = 0; i < 100; i++) {
    pthread_t thread;
    pthread_create(
        &thread, NULL, print_message_function, (void *) i);
    pthread_join(thread, NULL);
  }

  return 0;
}
