/* Definitions needed across loader/packer code */
#ifndef __KITESHIELD_DEFS_H
#define __KITESHIELD_DEFS_H

#include <stdint.h>

#define INT3 0xCC

/* Address at which the loader is initially loaded by the kernel on exec (ie.
 * the p_vaddr field in the binary). Note that if this is updated, the base
 * address in the linker script for the loader code must be updated
 * accordingly.
 */
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
struct rc4_key {
  uint8_t bytes[KEY_SIZE];
} __attribute__((packed));

/* Represents a function that contains a trap point */
struct function {
  void *start_addr;
  uint32_t len;
};

/* Represents a point in code at which we injected a single byte int3
 * instruction so that the program will trap into the ptrace runtime to decrypt
 * or encrypt the current function when entering or returning from it
 * respectively. We store a single trap_point_info struct at the end of the
 * loader code so the runtime has access to this info.
 */
struct trap_point {
  /* Address in program code of this trap point */
  void *addr;

  /* Byte that was overwritten by the int3, needed so we can overwrite and
   * execute the original instruction */
  uint8_t value;

  /* Info about function containing this trap point */
  struct function fcn;

  /* 1 if this is a ret instruction, 0 if this trap point marks the start of a
   * function (so the runtime knows whether to encrypt or decrypt respectively)
   */
  int is_ret : 1;
} __attribute__((packed));

struct trap_point_info {
  int num;
  struct trap_point arr[];
} __attribute__((packed));

#endif /* __KITESHIELD_DEFS_H */

