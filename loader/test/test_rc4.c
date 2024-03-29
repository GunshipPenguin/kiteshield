#include "attounit.h"
#include "common/include/rc4.h"

TEST_SUITE(rc4)

BEFORE_EACH() {}
AFTER_EACH() {}

/* Test vectors taken from RFC6229 */
TEST_CASE(rc4_40bit) {
  struct rc4_state rc4;
  unsigned char key[] = { 0x1, 0x2, 0x3, 0x4, 0x5 };
  unsigned char expected_stream[] = {
    0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
    0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
    0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5,
    0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19 };

  rc4_init(&rc4, key, sizeof(key));
  for (int i = 0; i < sizeof(expected_stream) / sizeof(unsigned char); i ++) {
    ASSERT_EQUAL_FMT(rc4_get_byte(&rc4), expected_stream[i], 0x%hhx);
  }
}

TEST_CASE(rc4_256bit) {
  struct rc4_state rc4;
  unsigned char key[] = {
    0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21,
    0xc1, 0x09, 0x16, 0x39, 0x08, 0xeb, 0xe5, 0x1d,
    0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37,
    0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a };
  unsigned char expected_stream[] = {
    0xdd, 0x5b, 0xcb, 0x00, 0x18, 0xe9, 0x22, 0xd4,
    0x94, 0x75, 0x9d, 0x7c, 0x39, 0x5d, 0x02, 0xd3,
    0xc8, 0x44, 0x6f, 0x8f, 0x77, 0xab, 0xf7, 0x37,
    0x68, 0x53, 0x53, 0xeb, 0x89, 0xa1, 0xc9, 0xeb };

  rc4_init(&rc4, key, sizeof(key));
  for (int i = 0; i < sizeof(expected_stream) / sizeof(unsigned char); i ++) {
    ASSERT_EQUAL_FMT(rc4_get_byte(&rc4), expected_stream[i], 0x%hhx);
  }
}
