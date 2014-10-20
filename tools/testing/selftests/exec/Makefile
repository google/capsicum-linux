CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
BINARIES = execveat
DEPS = execveat.symlink script subdir
all: $(BINARIES) $(DEPS)

subdir:
	mkdir -p $@
script:
	echo '#!/bin/sh' > $@
	echo 'exit $$*' >> $@
	chmod +x $@
execveat.symlink: execveat
	ln -s -f $< $@
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

run_tests: all
	./execveat

clean:
	rm -rf $(BINARIES) $(DEPS) subdir.moved execveat.moved
