/*
 * AttoUnit - A tiny header only unit testing framework for C
 * https://github.com/GunshipPenguin/attounit
 * ------------------------------------------------------------
 * Copyright (c) 2018, 2021 Rhys Rustad-Elliott
 * Distributed under the MIT license, see accompanying file LICENSE
 */
#include <stdio.h>
#include <string.h>

#ifndef __GNUC__
#error "Your compiler doesn't support GNU C extensions"
#endif

#define RED   "\x1B[1;31m"
#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

#define CHECK "\xE2\x9C\x93"
#define X_MARK "\xE2\x9C\x97"

#define MAX_NUM_TESTS 2048
#define MAX_TEST_NAME 256
#define MAX_SUITE_NAME 256

struct test_info {
  char test_name[MAX_TEST_NAME];
  char suite_name[MAX_SUITE_NAME];
  void (*func)();
  void (*setup)();
  void (*teardown)();
};

/* Pointers to test suite functions */
extern struct test_info tests[];
extern int num_test_cases;

extern int num_assertions;
extern int num_failed_assertions;
extern int curr_test_num;

#define GENERAL_BIN_ASSERT(a, b, op, desc, a_fmt, b_fmt) do { \
  num_assertions ++; \
  /* Deal with a and b not being pure by evaluating them only once */ \
  typeof(a) a_eval = a; \
  typeof(b) b_eval = b; \
  if (!(a_eval op b_eval)) { \
    num_failed_assertions ++; \
    printf(RED X_MARK " Assertion failed" RESET " at %s:%d (%s/%s)\n", \
      __FILE__, __LINE__, \
      tests[curr_test_num].suite_name, tests[curr_test_num].test_name); \
    printf("\t" #a " " #op " " #b "\n"); \
    printf("\tExpected " #a_fmt " " #desc " " #b_fmt "\n", a_eval, b_eval); \
  } \
} while(0)

#define GENERAL_UNARY_ASSERT(val, op, desc, val_fmt) do { \
  num_assertions ++; \
  /* Deal with val not being pure by evaluating it only once */ \
  typeof(val) val_eval = val; \
  if (!(op val_eval)) { \
    num_failed_assertions ++; \
    printf(RED X_MARK " Assertion failed" RESET " at %s:%d (%s/%s)\n", \
      __FILE__, __LINE__, \
      tests[curr_test_num].suite_name, tests[curr_test_num].test_name); \
    printf("\t" #op #val "\n"); \
    printf("\tExpected " #val_fmt " " #desc "\n", val_eval); \
  } \
} while(0)

#define ASSERT_TRUE(val) GENERAL_UNARY_ASSERT(val, , to be true, %d)
#define ASSERT_FALSE(val) GENERAL_UNARY_ASSERT(val, !, to be false, %d)

#define ASSERT_NULL(val) GENERAL_UNARY_ASSERT(val, !, to be null, %p)
#define ASSERT_NOT_NULL(val) GENERAL_UNARY_ASSERT(val, , to not be null, %p)

#define ASSERT_EQUAL(a, b) GENERAL_BIN_ASSERT(a, b, ==, to equal, %d, %d)
#define ASSERT_EQUAL_FMT(a, b, fmt) GENERAL_BIN_ASSERT(a, b, ==, to equal, fmt, fmt)

#define ASSERT_NOT_EQUAL(a, b) GENERAL_BIN_ASSERT(a, b, !=, to not equal, %d, %d)
#define ASSERT_NOT_EQUAL_FMT(a, b, fmt) GENERAL_BIN_ASSERT(a, b, !=, to not equal, fmt, fmt)

#define ASSERT_GREATER(a, b) GENERAL_BIN_ASSERT(a, b, >, to be greater than, %d, %d)
#define ASSERT_GREATER_FMT(a, b, fmt) GENERAL_BIN_ASSERT(a, b, >, to be greater than, fmt, fmt)

#define ASSERT_LESS(a, b) GENERAL_BIN_ASSERT(a, b, <, to be less than, %d, %d)
#define ASSERT_LESS_FMT(a, b, fmt) GENERAL_BIN_ASSERT(a, b, <, to be less than, fmt, fmt)

#define TEST_SUITE(suitename) \
  /* Static global information about this suite */ \
  static char *suite_name = #suitename; \

#define BEFORE_EACH() \
  static void before_each() \

#define AFTER_EACH() \
  static void after_each() \

#define TEST_CASE(casename) \
  /* Test case function prototype */ \
  void test_case_##casename(); \
  /* Test case constructor */ \
  __attribute__((constructor)) \
  void test_case_ctor_##casename() { \
    strcpy(tests[num_test_cases].test_name, #casename); \
    strcpy(tests[num_test_cases].suite_name, suite_name); \
    tests[num_test_cases].func = test_case_##casename; \
    tests[num_test_cases].setup = before_each; \
    tests[num_test_cases].teardown = after_each; \
    num_test_cases++; \
  } \
  void test_case_##casename()

#define TEST_MAIN() \
  void (*test_suite_funcs[MAX_NUM_TESTS])(); \
  int num_test_cases = 0; \
  int num_assertions = 0; \
  int num_failed_assertions = 0; \
  int curr_test_num = 0; \
  struct test_info tests[MAX_NUM_TESTS]; \
  int main() { \
    for (curr_test_num=0;curr_test_num<num_test_cases;curr_test_num++) { \
      tests[curr_test_num].setup(); \
      tests[curr_test_num].func(); \
      tests[curr_test_num].teardown(); \
    } \
    if (num_failed_assertions == 0) { \
      printf(GREEN CHECK " All assertions passed" RESET " (%d assertions in %d test cases)\n", num_assertions, num_test_cases); \
      return 0; \
    } else { \
      printf(RED X_MARK " %d assertions failed\n" RESET, num_failed_assertions); \
      return 1; \
    } \
  }
