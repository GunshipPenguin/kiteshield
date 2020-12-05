/* Definitions needed across loader/packer code */
#ifndef __KITESHIELD_DEFS_H
#define __KITESHIELD_DEFS_H

#include <stdint.h>

/* Base address to copy the application to before launching */
#define ENCRYPTED_APP_LOAD_ADDR 0x800000000ULL

/* Virtual address at which the stub loader is placed */
#define KITESHIELD_STUB_BASE 0x400000ULL

/* This struct is stored at a predefined offset in the loader code, allowing
 * the packer to copy the RC4 decryption key over the loader. */
#define KEY_SIZE 16
struct key_info {
  unsigned char key[KEY_SIZE];
} __attribute__((packed));


/* "byte substitution information", ie. information on bytes we had to remove
 * from the original program code to inject single byte int3 instructions for
 * function instrumentation. We store a single byte_sub_info struct at the end
 * of the loader code so the runtime has access to this info. This allows for
 * the original instruction to be executed at runtime.
 */
struct byte_sub {
  void *addr;
  uint8_t value;
} __attribute__((packed));

struct byte_sub_info {
  int num;
  struct byte_sub subs[];
} __attribute__((packed));

#endif /* __KITESHIELD_DEFS_H */

