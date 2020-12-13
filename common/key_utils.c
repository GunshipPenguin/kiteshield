#include "common/include/defs.h"

/* Key obfuscation / deobfuscation function.
 *
 * XORs the key with a variety of preset bytes from the loader code and
 * elsewhere in a convoluted fashion. Run before the key is embedded in the
 * loader code to ensure the naked key isn't stored on disk.
 *
 * Since this function just XORs the bytes of the key with a bunch of preset
 * bits, it is an involution (ie. it is its own inverse), thus it is used to
 * obfuscate the key in the loader code and then deobfuscate the key in the
 * loader code.
 */
void obf_deobf_key(
    struct rc4_key *old_key,
    struct rc4_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size)
{
  __builtin_memcpy(new_key, old_key, sizeof(*old_key));

  /* First XOR every byte of the key with a constant */
  for (int i = 0; i < sizeof(new_key->bytes); i++)
    new_key->bytes[i] ^= 0x55;

  /* Now we XOR the loader_index'th byte of the key with the loader_index'th
   * byte of the loader code where key_index starts at 0 and increments by 3
   * and loader_index starts at 0 and incremets by 22 until the end of the
   * loader code. */

  /* Skip the struct rc4_key of course, we just want the code */
  unsigned int loader_index = sizeof(struct rc4_key);
  unsigned int key_index = 0;
  while (loader_index < loader_bin_size) {
    new_key->bytes[key_index] ^= *((unsigned char *) loader_bin + loader_index);

    loader_index += 22;
    key_index = (key_index + 3) % sizeof(new_key->bytes);
  }
}

