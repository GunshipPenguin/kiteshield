#ifndef __KITESHIELD_RC4_H
#define __KITESHIELD_RC4_H

struct rc4_state {
  unsigned char S[256];
  int i;
  int j;
};

void rc4_init(struct rc4_state *rc4, unsigned char *key, unsigned int keylen);
unsigned char rc4_get_byte(struct rc4_state *rc4);

#endif /* __KITESHIELD_RC4_H */

