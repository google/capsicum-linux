CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
BINARIES = execveat
DEPS = execveat.symlink script execveat.ephemeral script.ephemeral subdir subdir.ephemeral subdir.ephemeral/script
all: $(BINARIES) $(DEPS)

subdir:
	mkdir -p $@
subdir.ephemeral:
	mkdir -p $@
subdir.ephemeral/script: | subdir.ephemeral
	echo '#!/bin/sh' > $@
	echo 'exit $$*' >> $@
	chmod +x $@
script:
	echo '#!/bin/sh' > $@
	echo 'exit $$*' >> $@
	chmod +x $@
script.ephemeral: script
	cp $< $@
execveat.symlink: execveat
	ln -s -f $< $@
execveat.ephemeral: execveat
	cp $< $@
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

run_tests: all
	./execveat

clean:
	rm -rf $(BINARIES) $(DEPS) subdir.moved execveat.moved
