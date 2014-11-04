CFLAGS += -Wall
TEST_PROGS = openat
CREATED = topfile symlinkdown subdir/bottomfile subdir/symlinkup subdir/symlinkout subdir/symlinkin subdir
all: $(TEST_PROGS)

include ../lib.mk

clean:
	rm -rf $(TEST_PROGS) $(CREATED)
