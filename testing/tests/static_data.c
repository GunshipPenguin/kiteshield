#include <stdio.h>
#include <assert.h>

static char arr[10000];

/* Tests whether data in .bss is completely zeroed (as it should be) when
 * mapped in */
int main()
{
  int i = 0;
  for (; i < sizeof(arr); i++) {
    assert(arr[i] == '\0');
  }

  printf("%u bytes of static data are zeroed\n", i);
  return 0;
}

