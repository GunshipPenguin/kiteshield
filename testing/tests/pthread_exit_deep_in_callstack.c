#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void fcn_5()
{
  printf("thread is is exiting\n");
  fflush(stdout);
  pthread_exit(NULL);
}

void fcn_4()
{
  fcn_5();
}

void fcn_3()
{
  fcn_4();
}

void fcn_2()
{
  fcn_3();
}

void *fcn_1(void *ptr)
{
  fcn_2();
}

int main()
{
  pthread_t thread;
  pthread_create(&thread, NULL, fcn_1, NULL);
  pthread_join(thread, NULL);

  return 0;
}
