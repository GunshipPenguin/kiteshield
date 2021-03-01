# Kiteshield Integration Test Infrastructure

This directory contains a suite of integration tests intended to exercise
Kiteshield's packer and loader to the greatest extent possible. Tests are
written as single-file C programs which are compiled, packed and run. Output on
standard out and exit status are then checked against expected values.

Notably, each test is compiled and packed in a large number of different
environments, spanning several Linux distros, C compilers, C libraries, and
compilation flags passed to the compiler when building the test. This ensures
as varied a set as possible of ELF binaries are passed to kiteshield for
packing and running. The tests for example, are compiled both statically and
dynamically linked, with various gcc and clang versions, and linked into both
glibc and musl libc. All these varied output binaries are then packed, run, and
have their output verified for correctness.

Several different Docker containers are used to create these environments. For
information on how this is done, see the shell scripts in this directory. They
are rather simple and should be self-documenting.

## Running Tests

```
./test.sh
```

## Adding New Tests

To add a new test called `mytest.c`, add your test code under `tests/mytest.c`
and expected output on standard output to a file called
`tests/expected_output/mytest`. Then add the following line to
`run_test_set.sh` (assuming 0 is the expected exit code of the test):

```
RUN_TEST mytest 0
```

