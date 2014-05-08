CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
BINARIES = seccomp
DEPS = testfile
all: $(BINARIES) $(DEPS)

testfile:
	echo 0123456789 > testfile
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

run_tests: all
	./seccomp testfile

clean:
	rm -f $(BINARIES) $(DEPS)
