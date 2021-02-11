#!/usr/bin/env bash

source output_wrappers.sh

BUILD_TESTS () {
  CC=$1
  CFLAGS=$2

  for C_SRC in tests/*.c
  do
    CC_OUPTPUT_FILE=$(mktemp)
    TEST_NAME=$(basename $C_SRC .c)
    $CC $CFLAGS $C_SRC -o out/$TEST_NAME > "$CC_OUPTPUT_FILE" 2>&1
    if [ $? -ne 0 ]
    then
      echo_red "Compilation failed in test $TEST_NAME"
      echo_red "*******COMPILER OUTPUT*******"
      cat $CC_OUPTPUT_FILE
      echo_red "*******END COMPILER OUTPUT*******"
      exit 1
    fi
  done

  return 0
}

BUILD_TESTS $1 $2

