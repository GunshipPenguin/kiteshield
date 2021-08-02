/* Spins off a new thread then exits in the thread group leader only. This hits
 * a corner case in ptrace on Linux whereby the thread group leader will hang
 * around as a zombie and cannot be waited on, despite having exited (see
 * comments in runtime.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void *print_message_function(void *ptr)
{
  char *message = (char *) ptr;
  printf("%s\n", message);
  fflush(stdout);
  sleep(1);
}

int main()
{
  pthread_t thread;
  char *message = "executing in new thread";
  int ret = pthread_create(
  &thread, NULL, print_message_function, (void *) message);

  /* Directly make an exit syscall, _exit(2) and exit(3) will both call
   * exit_group, which will terminate all threads in the group. */
  asm volatile (
      "mov $60, %%rax\n"
      "mov %0, %%edi\n"
      "syscall"
  :
  :   "rm" (0)
  :   "rax", "edi");
}
