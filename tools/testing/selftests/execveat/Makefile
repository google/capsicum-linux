DEPS=execveat.symlink script execveat.ephemeral script.ephemeral execveat subdir subdir.ephemeral subdir.ephemeral/script
all: $(DEPS)

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
execveat: execveat.c
	gcc $< -o $@

run_tests: execveat $(DEPS)
	./execveat

clean:
	rm -rf execveat $(DEPS) subdir.moved execveat.moved
