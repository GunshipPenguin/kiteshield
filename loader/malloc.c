#include "loader/include/malloc.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"

/* 20 MiB */
#define HEAP_SIZE (1 << 20)

void *heap_base = NULL;

struct block {
  size_t size;
  int in_use;
  struct block *next;
  struct block *prev;
};

void ks_malloc_init()
{
  heap_base = sys_mmap(NULL,
      HEAP_SIZE,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF_FMT((long) heap_base < 0, "mmap failure %d", heap_base);

  struct block *first = heap_base;
  first->size = HEAP_SIZE - sizeof(struct block);
  first->in_use = 0;
  first->next = NULL;
  first->prev = NULL;
}

void ks_malloc_deinit()
{
  int ret = sys_munmap(heap_base, HEAP_SIZE);
  DIE_IF_FMT(ret < 0, "munmap failed with %d", ret);
}

static struct block *split_block(size_t size, struct block *victim)
{
  DIE_IF(victim->size < size + sizeof(struct block),
      "not enough room for block split");

  if (victim->size - size <= sizeof(struct block)) {
    /* Not enough space to fit another block in, just return the victim
     * without splitting */
    return victim;
  }

  struct block *new_block =
    (struct block *) (((char *) victim) + sizeof(struct block) + size);
  new_block->size = victim->size - size - sizeof(struct block);
  new_block->in_use = 0;
  new_block->next = victim->next;
  new_block->prev = victim;

  victim->size = size;

  if (victim->next)
    victim->next->prev = new_block;

  victim->next = new_block;

  return victim;
}

int ks_malloc_get_n_blocks()
{
  int n = 0;
  struct block *curr = heap_base;
  while (curr != NULL) {
    n++;
    curr = curr->next;
  }

  return n;
}

void *ks_malloc(size_t size)
{
  DIE_IF(size == 0, "malloc of size 0, likely loader bug");

  struct block *curr = heap_base;
  struct block *target = NULL;
  while (curr != NULL) {
    if (curr->in_use) {
      curr = curr->next;
      continue;
    }

    if (curr->size == size) {
      target = curr;
      break;
    }

    if (curr->size >= size + sizeof(struct block)) {
      target = split_block(size, curr);
      break;
    }

    curr = curr->next;
  }

  DIE_IF(!target, "out of heap memory");
  target->in_use = 1;

  return target + 1;
}

void ks_free(void *ptr)
{
  struct block *block = ((struct block *) ptr) - 1;
  block->in_use = 0;

  /* Coalesce back */
  if (block->prev && !block->prev->in_use) {
    block->prev->size += block->size + sizeof(struct block);
    block->prev->next = block->next;

    if (block->next)
      block->next->prev = block->prev;

    block = block->prev;
  }

  /* Coalesce forward */
  if (block->next && !block->next->in_use) {
    block->size += block->next->size + sizeof(struct block);
    block->next = block->next->next;

    if (block->next)
      block->next->prev = block;
  }
}
