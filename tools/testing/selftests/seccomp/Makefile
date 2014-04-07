all: seccomp testfile

seccomp: seccomp.c
	gcc seccomp.c -o seccomp

testfile:
	echo 0123456789 > testfile

run_tests: seccomp testfile
	./seccomp testfile

clean:
	rm -f ./seccomp testfile
