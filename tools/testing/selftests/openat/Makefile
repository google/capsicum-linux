CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
BINARIES = openat
DEPS = subdir topfile subdir/bottomfile subdir/symlinkup subdir/symlinkout
all: $(BINARIES) $(DEPS)

subdir:
	mkdir -p subdir
topfile:
	echo 0123456789 > $@
subdir/bottomfile: | subdir
	echo 0123456789 > $@
subdir/symlinkup:
	ln -s ../topfile $@
subdir/symlinkout:
	ln -s /etc/passwd $@
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

run_tests: all
	./openat

clean:
	rm -rf $(BINARIES) $(DEPS)
