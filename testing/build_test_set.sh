#!/usr/bin/env bash

source testing/output_wrappers.sh

BUILD_TESTS () {
  CC=$1
  CFLAGS=$2
  OUT_DIR=$3

  for C_SRC in testing/tests/*.c
  do
    CC_OUTPUT_FILE=$(mktemp)
    TEST_NAME=$(basename $C_SRC .c)
    $CC $CFLAGS $C_SRC -o "$OUT_DIR/$TEST_NAME" > "$CC_OUTPUT_FILE" 2>&1
    if [ $? -ne 0 ]
    then
      echo_red "Compilation failed in test $TEST_NAME"
      echo_red "*******COMPILER OUTPUT*******"
      cat $CC_OUTPUT_FILE
      echo_red "*******END COMPILER OUTPUT*******"
      exit 1
    fi
  done

  return 0
}

BUILD_TESTS "$@"

