DEPS=execveat.symlink execveat.sh execveat.ephemeral execveat.sh.ephemeral execveat subdir subdir.ephemeral subdir.ephemeral/script
all: $(DEPS)

subdir:
	mkdir -p $@
subdir.ephemeral:
	mkdir -p $@
subdir.ephemeral/script: | subdir.ephemeral
	echo '#!/bin/sh' > $@
	echo 'exit $$*' >> $@
	chmod +x $@
execveat.sh:
	echo '#!/bin/sh' > $@
	echo './execveat $$*' >> $@
	chmod +x $@
execveat.symlink: execveat
	ln -s -f $< $@
execveat.ephemeral: execveat
	cp $< $@
execveat.sh.ephemeral: execveat.sh
	cp $< $@
execveat: execveat.c
	gcc $< -o $@

run_tests: execveat $(DEPS)
	./execveat

clean:
	rm -rf execveat $(DEPS) subdir.moved execveat.moved
