#include <stddef.h>
#include "common/include/defs.h"

/* Outer key obfuscation / deobfuscation function.
 *
 * XORs each byte of the outer key (the key used to encrypt the binary as a
 * whole, NOT the per-function keys) with a each byte of code/data in the
 * loader code. Run before the key is embedded in the loader code to ensure the
 * naked key isn't stored on disk and at load time to deobfuscate the key
 * before using it to decrypt the packed binary.
 *
 * This method of obfuscating the outer key has the nice added side effect of
 * effectively checksumming the loader code. If a reverse-engineer patches out
 * some bytes in the loader code with nops, the outer key will be deobfuscated
 * incorrectly, and the program will undoubtedly crash and burn. Furthermore,
 * it will crash somewhere in the packed code (ie. not here), thus drawing
 * attention away from this "checksumming" code.
 *
 * Since this function just XORs the bytes of the key with a bunch of preset
 * bits, it is an involution (ie. it is its own inverse), thus it is used to
 * obfuscate the key in the loader code and then deobfuscate the key in the
 * loader code.
 */
void obf_deobf_outer_key(
    struct rc4_key *old_key,
    struct rc4_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size)
{
  __builtin_memcpy(new_key, old_key, sizeof(*old_key));

  /* Skip the struct rc4_key of course, we just want the code */
  unsigned int loader_index = sizeof(struct rc4_key);
  unsigned int key_index = 0;
  while (loader_index < loader_bin_size) {
    new_key->bytes[key_index] ^= *((unsigned char *) loader_bin + loader_index);

    loader_index ++;
    key_index = (key_index + 1) % sizeof(new_key->bytes);
  }
}

/* Trap point info obfuscation / deobfuscation function.
 *
 * Obfuscates the passed in trap point info so we're not storing the
 * per-function keys (and function/trap point metadata) naked on disk.
 *
 * Unlike the outer key, we're not going for a checksumming like effect here,
 * so just use a simple incrementing XOR to obfuscate all the information in
 * the trap_point_info struct.
 *
 * As above, this function is an involution.
 */
void obf_deobf_tp_info(
    struct trap_point_info *tp_info) {
  size_t size = (sizeof(struct trap_point) * tp_info->ntps) +
                (sizeof(struct function) * tp_info->nfuncs);

  /* Skip the data actually in the struct trap_point_info and not the flexible
   * array as we need it to calculate the size to obfuscate/deobfuscate */
  uint8_t *data = (uint8_t *) tp_info + sizeof(struct trap_point_info);
  for (size_t i = 0; i < size; i++) {
    data[i] = data[i] ^ (i % 256);
  }
}

