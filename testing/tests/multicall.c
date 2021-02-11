#include <stdio.h>

int call_count = 0;

int func()
{
  call_count++;
  printf("Call count is now %d\n", call_count);
}

int main()
{
  /* Call func repeatedly to ensure it's being correctly encrypted/decrypted
   * on each call */
  int i;
  for (i = 0; i < 5; i++) {
    func();
  }

  return 0;
}

