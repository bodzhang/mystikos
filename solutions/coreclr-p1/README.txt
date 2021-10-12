To build this solutions, from the base of the repository:
user@accvm-icelk:~/mystikos$ make -j
user@accvm-icelk:~/mystikos$cd solutions/coreclr-p1
user@accvm-icelk:~/mystikos/solutions/coreclr-p1$ make -j

# To run all the tests
user@accvm-icelk:~/mystikos/solutions/coreclr-p1$ make run

# to run one test, modify the variable TEST_CASE in Makefile to the
path to test dll, and run
user@accvm-icelk:~/mystikos/solutions/coreclr-p1$ make run-ext2
user@accvm-icelk:~/mystikos/solutions/coreclr-p1$ make TARGET=linux run-ext2
user@accvm-icelk:~/mystikos/solutions/coreclr-p1$ make run-ext2-gdb

Tests in files pr1-FAILED-others fail currently. The stdout
for tests in pr1-FAILED-others is documented in the file. These need to be
analysed further to add to test-suite.
