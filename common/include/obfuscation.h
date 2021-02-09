#ifndef __KITESHIELD_OBFUSCATION_H
#define __KITESHIELD_OBFUSCATION_H

#include "common/include/defs.h"

void obf_deobf_outer_key(struct rc4_key *old_key,
                         struct rc4_key *new_key,
                         unsigned char *loader_bin,
                         unsigned int loader_bin_size);

void obf_deobf_tp_info(
    struct trap_point_info *tp_info);

#endif /* __KITESHIELD_OBFUSCATION_H */

