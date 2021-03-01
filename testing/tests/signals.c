#include <stdio.h>
#include <signal.h>

void handler(int sig)
{
  printf("Caught signal %d\n", sig);
}

int main()
{
  struct sigaction sa;
  sa.sa_handler = handler;
  sigaction(SIGALRM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);

  raise(SIGALRM);
  raise(SIGINT);
  raise(SIGUSR1);
  raise(SIGSEGV);

  return 0;
}

