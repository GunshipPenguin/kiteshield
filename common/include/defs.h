/* Definitions needed across loader/packer code */
#ifndef __KITESHIELD_DEFS_H
#define __KITESHIELD_DEFS_H

/* Virtual address at which the stub loader is placed */
#define KITESHIELD_STUB_BASE 0x400000ULL

/* This struct is stored at a predefined offset in the loader code, allowing
 * the packer to copy the RC4 decryption key over the loader. */
#define KEY_SIZE 16
struct key_info {
  unsigned char key[KEY_SIZE];
} __attribute__((packed));

#endif /* __KITESHIELD_DEFS_H */

