#ifndef __KITESHIELD_MALLOC_H
#define __KITESHIELD_MALLOC_H

#include <stddef.h>

void ks_malloc_init();
void ks_malloc_deinit();

void *ks_malloc(size_t size);
void ks_free(void *ptr);

int ks_malloc_get_n_blocks();

#endif /* __KITESHIELD_MALLOC_H */
