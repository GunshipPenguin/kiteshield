#include "common/include/rc4.h"

/* https://en.wikipedia.org/wiki/RC4#Description */
void rc4_init(struct rc4_state *rc4, unsigned char *key, unsigned int keylen)
{
  for (unsigned int i = 0; i < 256; i++) {
    rc4->S[i] = (unsigned char) i;
  }

  unsigned int j = 0;
  for (unsigned int i = 0; i < 256; i++) {
    j = (j + rc4->S[i] + key[i % keylen]) % 256;

    unsigned char temp = rc4->S[i];
    rc4->S[i] = rc4->S[j];
    rc4->S[j] = temp;
  }

  rc4->i = 0;
  rc4->j = 0;
}

unsigned char rc4_get_byte(struct rc4_state *rc4)
{
  rc4->i = (rc4->i + 1) % 256;
  rc4->j = (rc4->j + rc4->S[rc4->i]) % 256;

  unsigned char temp = rc4->S[rc4->i];
  rc4->S[rc4->i] = rc4->S[rc4->j];
  rc4->S[rc4->j] = temp;

  return rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j]) % 256];
}

