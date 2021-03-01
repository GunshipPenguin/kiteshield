#!/usr/bin/env bash

source testing/output_wrappers.sh

RUN_TEST () {
  TEST_NAME=$1
  EXPECTED_STATUS=$2

  printf "%-70s" "Running test $TEST_NAME for $TEST_ID"

  TEST_BINARY="${TEST_NAME}.ks"
  EXPECTED_OUTPUT=$(cat ./testing/tests/expected_outputs/$TEST_NAME)
  ACTUAL_OUTPUT=$($TEST_DIR/$TEST_BINARY)
  ACTUAL_STATUS=$?

  if [ $ACTUAL_STATUS -ne $EXPECTED_STATUS ]
  then
    echo_red "$X_MARK failed"

    echo_red "Status differs from expected status in $TEST_NAME"
    echo_red "Expected status: $EXPECTED_STATUS, actual status $ACTUAL_STATUS"
    exit 1;
  elif [ "$ACTUAL_OUTPUT" != "$EXPECTED_OUTPUT" ]
  then
    echo_red "$X_MARK failed"

    echo_red "Output differs from expected output in $TEST_NAME"
    echo_red "*******ACTUAL OUTPUT*******"
    echo "$ACTUAL_OUTPUT"
    echo_red "*******EXPECTED OUTPUT*******"
    echo "$EXPECTED_OUTPUT"
    echo_red "*******END EXPECTED OUTPUT*******"

    exit 1
  else
    echo_green "$CHECK_MARK passed"
  fi

  return 0;
}

TEST_DIR=$1
TEST_ID=$2

RUN_TEST helloworld 0
RUN_TEST nonzero_exit 7
RUN_TEST multicall 0
RUN_TEST recursion 0
RUN_TEST file_read 0
RUN_TEST longjmp 0
RUN_TEST mutual_recursion 0
RUN_TEST prime_sieve 0
RUN_TEST static_data 0
