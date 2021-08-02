/* Spins a bunch of threads in fcn_1, which wait to go into fcn_2 in sequence
 * where they sequentially print their thread ID. Tests that we don't
 * accidentally encrypt fcn_1 when returning from it if other threads are
 * executing in it. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

long curr_thread = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void fcn_2(long id)
{
  printf("thread %d is in fcn_2\n", id);
  fflush(stdout);

  pthread_mutex_lock(&mutex);
  curr_thread++;
  pthread_mutex_unlock(&mutex);
}

void *fcn_1(void *ptr)
{
  long id = (long) ptr;

  while (1) {
    long val;

    pthread_mutex_lock(&mutex);
    val = curr_thread;
    pthread_mutex_unlock(&mutex);

    if (id == val) {
      fcn_2(id);
      break;
    }
  }
}

int main()
{
#define NTHREADS 5

  pthread_t threads[NTHREADS];
  long i;
  for (i = 0; i < NTHREADS; i++)
    pthread_create(&threads[i], NULL, fcn_1, (void *) i);

  for (i = 0; i < NTHREADS; i++)
    pthread_join(threads[i], NULL);

  return 0;
}
