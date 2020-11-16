#ifndef __KITESHIELD_RC4_H_
#define __KITESHIELD_RC4_H_

struct rc4_state {
  unsigned char S[256];
  int i;
  int j;
};

void rc4_init(struct rc4_state *rc4, unsigned char *key, unsigned int keylen);
unsigned char rc4_get_byte(struct rc4_state *rc4);

#endif
