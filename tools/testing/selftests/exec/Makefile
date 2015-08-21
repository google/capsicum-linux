CFLAGS += -Wall
TEST_PROGS := execveat
CREATED = subdir subdir.moved execveat.symlink exeveat.moved execveat.denatured script non-script
all: $(TEST_PROGS)

include ../lib.mk

clean:
	rm -rf $(TEST_PROGS) $(CREATED) xxxxx* *.ephemeral
