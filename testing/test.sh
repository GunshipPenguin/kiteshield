#!/usr/bin/env bash

source testing/output_wrappers.sh

RUN_CONTAINER_TESTS () {
  IMG=$1
  CC=$2
  CFLAGS=$3
  TEST_ID="$IMG/$CC/\"$CFLAGS\""

  if [ -z "$CFLAGS" ]
  then
    TEST_BIN_DIR="testing/out/$IMG/$CC/NOCFLAGS/"
  else
    TEST_BIN_DIR="testing/out/$IMG/$CC/${CFLAGS// /_}/"
  fi

  echo_bold "Starting test suite $TEST_ID"

  rm -rf "$TEST_BIN_DIR"
  mkdir -p "$TEST_BIN_DIR"

  # 2:43 with this
  printf "%-70s" "Building test container for $TEST_ID"
  #docker build -t ${IMG}-ks-test - < testing/dockerfiles/Dockerfile-${IMG}

  if [ $? -ne 0 ]
  then
    echo_red -e "Error building docker image"
    exit 1
  else
    echo_green "$CHECK_MARK done"
  fi

  printf "%-70s" "Building tests for $TEST_ID"
  START=$SECONDS
  docker run \
    --rm \
    --cap-add=SYS_PTRACE \
    --user 1000:1000 \
    --volume $(pwd):/kiteshield \
    --workdir=/kiteshield \
    ${IMG}-ks-test testing/build_test_set.sh "$CC" "$CFLAGS" "$TEST_BIN_DIR"

  if [ $? -ne 0 ]
  then
    echo -e "Failure building tests"
    exit 1
  else
    echo_green "$CHECK_MARK done"
  fi
  END=$SECONDS
  echo "Time needed for build: $((END - START))"

  START=$SECONDS
  printf "%-70s" "Packing test binaries for $TEST_ID"
  for UNPACKED_BIN in $TEST_BIN_DIR/*
  do
    PACKER_OUTPUT=$(mktemp)
    packer/kiteshield -v $UNPACKED_BIN ${UNPACKED_BIN}.ks > "$PACKER_OUTPUT" 2>&1
    if [ $? -ne 0 ]
    then
      echo_red "$X_MARK failed"
      echo -e "*******PACKER OUTPUT*******"
      cat $PACKER_OUTPUT
      echo -e "*******END PACKER OUTPUT*******"
      exit 1
    fi
  done

  echo_green "$CHECK_MARK done"

  END=$SECONDS
  echo "Time needed for pack: $((END - START))"

  START=$SECONDS
  docker run \
    --rm \
    --cap-add=SYS_PTRACE \
    --user 1000:1000 \
    --volume $(pwd):/kiteshield \
    --workdir=/kiteshield \
    ${IMG}-ks-test testing/run_test_set.sh $TEST_BIN_DIR $TEST_ID

  if [ $? -ne 0 ]
  then
    echo_red "Failure running tests"
    exit 1
  else
    echo_green "All tests passed for suite $TEST_ID"
  fi

  END=$SECONDS
  echo "Time needed for test: $((END - START))"
}

RUN_CONTAINER_TESTS_CFLAGS () {
  RUN_CONTAINER_TESTS $1 $2 ""
  RUN_CONTAINER_TESTS $1 $2 "-static"
  RUN_CONTAINER_TESTS $1 $2 "-static -O3"
}

RUN_CONTAINER_TESTS_CFLAGS "$@"
