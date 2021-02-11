#include <stdio.h>
#include <string.h>

int main()
{
  int primes[100];
  int arr_size = sizeof(primes) / sizeof(int);
  int i, j;

  memset(primes, 1, sizeof(primes));

  for (i = 2; i < 10; i++) {
    if (!primes[i]) continue;
    primes[i] = 1;

    for (j = i * 2; j < arr_size; j+=i) {
      primes[j] = 0;
    }
  }

  for (i = 2; i < arr_size; i++) {
    if (primes[i])
      printf("%d\n", i);
  }

  return 0;
}

