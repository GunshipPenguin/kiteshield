#include <stdio.h>

int is_odd(int n);

int is_even(int n)
{
  if (n == 0) return 1;
  else return is_odd(n - 1);
}

int is_odd(int n)
{
  if (n == 0) return 0;
  else return is_even(n - 1);
}

int main()
{
  printf("Is 0 even? %d\n", is_even(0));
  printf("Is 1 even? %d\n", is_even(1));
  printf("Is 2 even? %d\n", is_even(2));
  printf("Is 3 even? %d\n", is_even(3));
  printf("Is 128 even? %d\n", is_even(128));
  printf("Is 887 even? %d\n", is_even(887));
  printf("Is 1284 even? %d\n", is_even(1284));

  printf("\n");

  printf("Is 0 odd? %d\n", is_odd(0));
  printf("Is 1 odd? %d\n", is_odd(1));
  printf("Is 2 odd? %d\n", is_odd(2));
  printf("Is 3 odd? %d\n", is_odd(3));
  printf("Is 128 odd? %d\n", is_odd(128));
  printf("Is 887 odd? %d\n", is_odd(887));
  printf("Is 1284 odd? %d\n", is_odd(1284));

  return 0;
}

