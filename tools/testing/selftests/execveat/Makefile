all: execveat.symlink execveat.sh execveat.ephemeral execveat

execveat.sh:
	echo '#!/bin/sh' > execveat.sh
	echo './execveat $$*' >> execveat.sh
	chmod +x execveat.sh
execveat.symlink: execveat
	ln -s -f execveat execveat.symlink
execveat.ephemeral: execveat
	cp execveat execveat.ephemeral
execveat: execveat.c
	gcc execveat.c -o execveat

run_tests: all
	./execveat

clean:
	rm -f ./execveat ./execveat.symlink ./execveat.sh
