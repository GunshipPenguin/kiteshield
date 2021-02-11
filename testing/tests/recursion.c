#include <stdio.h>

int fact(int n)
{
  if (n == 0) return 1;
  else return n * fact(n-1);
}

int main()
{
  printf("%u\n", fact(30));
  return 0;
}
