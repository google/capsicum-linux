CFLAGS += -Wall -g
BINARIES = clone clone4
all: $(BINARIES)

%: %.c clonetest.h
	$(CC) $(CFLAGS) -o $@ $<

TEST_PROGS := clone clone4

include ../lib.mk

clean:
	rm -rf $(BINARIES)
