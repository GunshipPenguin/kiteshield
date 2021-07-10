#include "attounit.h"
#include "loader/include/malloc.h"

TEST_SUITE(malloc)

BEFORE_EACH() {
  ks_malloc_init();
}
AFTER_EACH() {
  ks_malloc_deinit();
}

TEST_CASE(malloc_basic) {
  void *ptr = ks_malloc(16);
  ASSERT_NOT_NULL(ptr);
  ks_free(ptr);

  ASSERT_EQUAL(ks_malloc_get_n_blocks(), 1);
}

TEST_CASE(malloc_memset) {
  char *ptr = ks_malloc(32 * sizeof(char));
  for (int i = 0; i < 32; i++)
    ptr[i] = i;

  /* Fill a ton of blocks with junk, test will verify none overlap the first
   * one allocated */
  for (int i = 1; i < 1000; i++) {
    void *ptr = ks_malloc(i);
    memset(ptr, i, i);
  }

  for (int i = 0; i < 32; i++)
    ASSERT_EQUAL(ptr[i], i);
}

TEST_CASE(malloc_coalesce) {
  int nblocks = 1000;
  void *ptrs[nblocks];

  ASSERT_EQUAL(ks_malloc_get_n_blocks(), 1);

  for (int i = 1; i < nblocks; i++) {
    ptrs[i] = ks_malloc(i);
    ASSERT_EQUAL(ks_malloc_get_n_blocks(), i + 1);
  }

  for (int i = 1; i < nblocks; i++)
    ks_free(ptrs[i]);

  ASSERT_EQUAL(ks_malloc_get_n_blocks(), 1);
}

TEST_CASE(malloc_coalesce_with_memset) {
  int nblocks = 1000;
  void *ptrs[nblocks];

  ASSERT_EQUAL(ks_malloc_get_n_blocks(), 1);

  for (int i = 1; i < nblocks; i++) {
    ptrs[i] = ks_malloc(i);
    memset(ptrs[i], 0, i);
    ASSERT_EQUAL(ks_malloc_get_n_blocks(), i + 1);
  }

  for (int i = 1; i < nblocks; i++)
    ks_free(ptrs[i]);

  ASSERT_EQUAL(ks_malloc_get_n_blocks(), 1);
}
