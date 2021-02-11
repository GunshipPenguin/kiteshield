#include <stdio.h>
#include <setjmp.h>

static jmp_buf buf;

void second()
{
  printf("second\n");
  longjmp(buf,1);
}

void first()
{
  second();
  printf("first\n");
}

int main()
{
  if (setjmp(buf) == 0) {
    first();
  } else {
    printf("main\n");
  }

  return 0;
}

