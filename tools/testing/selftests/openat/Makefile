DEPS=openat subdir topfile subdir/bottomfile subdir/symlinkup subdir/symlinkout
all: $(DEPS)

subdir:
	mkdir -p subdir
topfile:
	echo 0123456789 > $@
subdir/bottomfile: | subdir
	echo 0123456789 > $@
subdir/symlinkup:
	ln -s ../topfile $@
subdir/symlinkout:
	ln -s /etc/passwd $@
openat: openat.c
	gcc $< -o $@

run_tests: $(DEPS)
	./openat

clean:
	rm -rf $(DEPS)
