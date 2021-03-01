cd ..

make clean
make

parallel --halt now,fail=1 -j5 --lb <<EOF
testing/test.sh centos-8 gcc
testing/test.sh centos-8 clang

testing/test.sh centos-7 gcc
testing/test.sh centos-7 clang

testing/test.sh alpine gcc
testing/test.sh alpine clang

testing/test.sh fedora gcc
testing/test.sh fedora clang

testing/test.sh ubuntu-trusty gcc
testing/test.sh ubuntu-trusty clang-3.6

testing/test.sh ubuntu-xenial gcc
testing/test.sh ubuntu-xenial clang-3.5
testing/test.sh ubuntu-xenial clang-4.0
testing/test.sh ubuntu-xenial clang-5.0

testing/test.sh ubuntu-bionic gcc-5
testing/test.sh ubuntu-bionic gcc-6
testing/test.sh ubuntu-bionic gcc-7
testing/test.sh ubuntu-bionic gcc-8
testing/test.sh ubuntu-bionic clang-4.0
testing/test.sh ubuntu-bionic clang-5.0
testing/test.sh ubuntu-bionic clang-6.0
testing/test.sh ubuntu-bionic clang-7
testing/test.sh ubuntu-bionic clang-8
testing/test.sh ubuntu-bionic clang-9
testing/test.sh ubuntu-bionic clang-10

testing/test.sh ubuntu-focal gcc-7
testing/test.sh ubuntu-focal gcc-8
testing/test.sh ubuntu-focal gcc-9
testing/test.sh ubuntu-focal gcc-10
testing/test.sh ubuntu-focal clang-6.0
testing/test.sh ubuntu-focal clang-7
testing/test.sh ubuntu-focal clang-8
testing/test.sh ubuntu-focal clang-9
testing/test.sh ubuntu-focal clang-10
testing/test.sh ubuntu-focal clang-11
EOF

