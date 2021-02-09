#ifndef __KITESHIELD_KEY_UTILS_H
#define __KITESHIELD_KEY_UTILS_H

#include "common/include/defs.h"

void obf_deobf_outer_key(struct rc4_key *old_key,
                         struct rc4_key *new_key,
                         unsigned char *loader_bin,
                         unsigned int loader_bin_size);

#endif /* __KITESHIELD_KEY_UTILS_H */

