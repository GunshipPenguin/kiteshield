/* Definitions needed across loader/packer code */
#ifndef __KITESHIELD_DEFS_H
#define __KITESHIELD_DEFS_H

#include <stdint.h>

/* Address at which the loader is initially loaded by the kernel on exec (ie.
 * the p_vaddr field in the binary) */
#define LOADER_ADDR 0x400000ULL

/* Address at which the packed binary is initially loaded by the kernel on
 * exec (ie. the p_vaddr field in the binary) */
#define PACKED_BIN_ADDR 0xA00000ULL

/* Base address the loader will copy the packed binary to before launching */
#define UNPACKED_BIN_LOAD_ADDR 0x800000000ULL

/* Base address at which the loader code will load ld.so */
#define INTERP_LOAD_ADDR 0xB00000000ULL

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
  void *func_start;
  void *func_end;
  int is_ret : 1;
} __attribute__((packed));

struct byte_sub_info {
  int num;
  struct byte_sub subs[];
} __attribute__((packed));

#endif /* __KITESHIELD_DEFS_H */

