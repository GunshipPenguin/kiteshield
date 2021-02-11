#!/usr/bin/env bash

source output_wrappers.sh

RUN_CONTAINER_TESTS () {
  IMG=$1
  CC=$2
  CFLAGS=$3
  TEST_ID="$IMG/$CC/\"$CFLAGS\""

  echo_bold "Test suite $TEST_ID"

  rm -r testing/out
  mkdir -p testing/out

  echo -ne "\tBuilding test container... "
  docker build \
    --quiet \
    -t ${IMG}-ks-test \
    -f testing/dockerfiles/Dockerfile-${IMG} . > /dev/null

  if [ $? -ne 0 ]
  then
    echo -e "\tError building docker image"
    exit 1
  else
    echo_green "$CHECK_MARK done"
  fi

  echo -ne "\tBuilding tests... "
  docker run \
    --rm \
    --cap-add=SYS_PTRACE \
    --user 1000:1000 \
    --volume $(pwd):/kiteshield \
    --workdir=/kiteshield/testing \
    ${IMG}-ks-test ./build_test_set.sh $CC $CFLAGS

  if [ $? -ne 0 ]
  then
    echo -e "\tFailure building tests"
    exit 1
  else
    echo_green "$CHECK_MARK done"
  fi

  echo -ne "\tPacking test binaries... "
  for UNPACKED_BIN in testing/out/*
  do
    PACKER_OUTPUT=$(mktemp)
    packer/kiteshield -v $UNPACKED_BIN ${UNPACKED_BIN}.ks > "$PACKER_OUTPUT"
    if [ $? -ne 0 ]
    then
      echo -e "\tFailure packing test binary $UNPACKED_BIN for $TEST_ID"
      echo -e "\t*******PACKER OUTPUT*******"
      cat $PACKER_OUTPUT
      echo -e "\t*******END PACKER OUTPUT*******"
      exit 1
    fi
  done

  echo_green "$CHECK_MARK done"

  echo -e "\tRunning tests:"
  docker run \
    --rm \
    --cap-add=SYS_PTRACE \
    --user 1000:1000 \
    --volume $(pwd):/kiteshield \
    --workdir=/kiteshield/testing \
    ${IMG}-ks-test ./run_test_set.sh

  if [ $? -ne 0 ]
  then
    echo_red "\tFailure running tests"
    exit 1
  else
    echo_green "\tAll tests passed for suite $TEST_ID"
  fi
}

RUN_CONTAINER_TESTS_CFLAGS () {
  RUN_CONTAINER_TESTS $1 $2 ""
  RUN_CONTAINER_TESTS $1 $2 "-static"
  RUN_CONTAINER_TESTS $1 $2 "-static -O3"
}

cd ..

make clean
make

RUN_CONTAINER_TESTS_CFLAGS ubuntu-trusty gcc
RUN_CONTAINER_TESTS_CFLAGS ubuntu-trusty clang-3.6

RUN_CONTAINER_TESTS_CFLAGS ubuntu-xenial gcc
RUN_CONTAINER_TESTS_CFLAGS ubuntu-xenial clang-3.5
RUN_CONTAINER_TESTS_CFLAGS ubuntu-xenial clang-4.0
RUN_CONTAINER_TESTS_CFLAGS ubuntu-xenial clang-5.0

RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic gcc-5
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic gcc-6
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic gcc-7
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic gcc-8
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-4.0
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-5.0
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-6.0
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-7
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-8
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-9
RUN_CONTAINER_TESTS_CFLAGS ubuntu-bionic clang-10

RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal gcc-7
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal gcc-8
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal gcc-9
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal gcc-10
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-6.0
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-7
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-8
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-9
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-10
RUN_CONTAINER_TESTS_CFLAGS ubuntu-focal clang-11

