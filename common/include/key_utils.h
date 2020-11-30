#ifndef KITESHIELD_KEY_UTILS_H_
#define KITESHIELD_KEY_UTILS_H_

#include "common/include/defs.h"

void obf_deobf_key(struct key_info *old_ki, struct key_info *new_ki,
                   unsigned char *loader_bin, unsigned int loader_bin_size);

#endif
