#!/usr/bin/env bash

source output_wrappers.sh

RUN_TEST () {
  TEST_NAME=$1
  BINARY=$2
  EXPECTED_STATUS=$3
  EXPECTED_OUTPUT=$4

  printf "\t%-60s" "Running test $TEST_NAME"
  ACTUAL_OUTPUT=$(./out/$BINARY)
  ACTUAL_STATUS=$?

  if [[ $ACTUAL_STATUS -ne $EXPECTED_STATUS ]]
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


}

RUN_RT_AND_NORT_TESTS () {
  BIN_NAME=$1
  EXPECTED_STATUS=$2
  EXPECTED_OUTPUT=$(cat ./tests/expected_outputs/$BIN_NAME)

  RUN_TEST "(layer 1) ${BIN_NAME}" "${BIN_NAME}.ks.nort" $EXPECTED_STATUS "$EXPECTED_OUTPUT"
  RUN_TEST "(layer 1/2) ${BIN_NAME}" "${BIN_NAME}.ks" $EXPECTED_STATUS "$EXPECTED_OUTPUT"

  return 0;
}

# Single-threaded tests
RUN_RT_AND_NORT_TESTS helloworld 0
RUN_RT_AND_NORT_TESTS multicall 0
RUN_RT_AND_NORT_TESTS recursion 0
RUN_RT_AND_NORT_TESTS file_read 0
RUN_RT_AND_NORT_TESTS longjmp 0
RUN_RT_AND_NORT_TESTS mutual_recursion 0
RUN_RT_AND_NORT_TESTS prime_sieve 0
RUN_RT_AND_NORT_TESTS static_data 0
RUN_RT_AND_NORT_TESTS signals 0

# Muti-threaded tests
RUN_RT_AND_NORT_TESTS pthread_simple 0
RUN_RT_AND_NORT_TESTS pthread_many_threads 0
RUN_RT_AND_NORT_TESTS pthread_shared_stacktraces 0
RUN_RT_AND_NORT_TESTS pthread_exit_deep_in_callstack 0
RUN_RT_AND_NORT_TESTS pthread_with_fork 0
RUN_RT_AND_NORT_TESTS pthread_thread_leader_exit 0
RUN_RT_AND_NORT_TESTS fork_simple 0
RUN_RT_AND_NORT_TESTS fork_many 0
RUN_RT_AND_NORT_TESTS fork_chain 0
RUN_RT_AND_NORT_TESTS fork_exec 0
