CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
BINARIES = openat
DEPS = subdir topfile symlinkdown subdir/bottomfile subdir/symlinkup subdir/symlinkout subdir/symlinkin
all: $(BINARIES) $(DEPS)

subdir:
	mkdir -p subdir
topfile:
	echo 0123456789 > $@
subdir/bottomfile: | subdir
	echo 0123456789 > $@
subdir/symlinkup: | subdir
	ln -s ../topfile $@
subdir/symlinkout: | subdir
	ln -s /etc/passwd $@
subdir/symlinkin: | subdir
	ln -s bottomfile $@
symlinkdown:
	ln -s subdir/bottomfile $@
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

run_tests: all
	./openat

clean:
	rm -rf $(BINARIES) $(DEPS)
