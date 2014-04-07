Capsicum Object-Capabilities on Linux
=====================================

This repository is used for the development of
[Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/) object
capabilities in the Linux kernel.  Overall status of the
Capsicum for Linux project is described at
[capsicum-linux.org](http://capsicum-linux.org/index.html).

This functionality is originally based on:

 - the original Capsicum implementation in FreeBSD 9.x and 10.x,
   written by Robert Watson and Jonathan Anderson.
 - the
   [Linux kernel implementation](http://git.chromium.org/gitweb/?p=chromiumos/third_party/kernel-capsicum.git;a=shortlog;h=refs/heads/capsicum)
   written by Meredydd Luff in 2012.

The current functionality is based on the 4.2 upstream kernel.

Branch Status
-------------

The `capsicum` branch is the main Capsicum development branch, which is under active
development (and so may contain in-progress code); the
[capsicum-test](https://github.com/google/capsicum-test) repository is normally kept
in sync with this branch.

There are also four (per-version) topic branches, which hold patchsets that can be applied
on top of an upstream kernel version.  These branches are **frequently rebased**, either
because a new upstream release candidate has become available, or because a fix to
the `capsicum` branch has been back-applied to the topic branches

![Capsicum branch structure](capsicum-branches.png)

The topic branches are:

 - `capsicum-hooks-<ver>`: Capability file descriptors.
 - `procdesc-<ver>`: Process descriptors.
 - `misc-<ver>`: Other kernel changes not specific to Capsicum.
 - `no-upstream-<ver>`: Local changes for development convenience.

A merge of the latest versions of these four topic branches should yield a codebase
that is the same as the current `capsicum` branch (although this sometimes lags
behind as this requires manual merging).


Functionality Overview
----------------------

Capsicum introduces a new kind of file descriptor, a *capability* file
descriptor, which has a limited set of *rights* associated with it.  Operations
on a capability FD that are not allowed by the associated rights are rejected
(with `ENOTCAPABLE`), and the rights associated with a capability FD can only
be narrowed, not widened.

Capsicum also introduces *capability mode*, which disables (with `ECAPMODE`)
all syscalls that access any kind of global namespace; this is mostly (but not
completely) implemented in userspace as a seccomp-bpf filter.

See [Documentation/security/capsicum.txt](Documentation/security/capsicum.txt)
for more details

As process management normally involves a global namespace (that of `pid_t`
values), Capsicum also introduces a *process descriptor* and related syscalls,
which allows processes to be manipulated as another kind of file descriptor.
This functionality is based on Josh Triplett's proposed clonefd patches.


Building
--------

Capsicum support is currently included for x86 variants and user-mode Linux; the
following config settings need to be enabled:

 - `CONFIG_SECURITY_CAPSICUM` enables Capsicum capabilities
 - `CONFIG_CLONE4` enables the clone4(2) system call, which is needed for...
 - `CONFIG_CLONEFD` enables the clonefd functionality that process descriptors
   are built on.

The following configuration options are useful for development:

 - `CONFIG_DEBUG_KMEMLEAK`: enable kernel memory leak detection.
 - `CONFIG_DEBUG_BUGVERBOSE`: verbose bug reporting.

User-mode Linux can be used for Capsicum testing, and requires the following
additional configuration parameters:

 - `CONFIG_DEBUG_FS`: enable debug filesystem.


Testing
-------

The test suite for Capsicum is held in a separate
[capsicum-test](https://github.com/google/capsicum-test) repository, to allow
the tests to be easily shared between Linux and FreeBSD.

This repository also includes kernel self-tests for some aspects of Capsicum
functionality, specifically:

 - `selftests/openat`: tests of openat(2) and the new `O_BENEATH` flag for it.
 - `selftests/clone`: tests of the clonefd functionality used for process
   descriptors.

There are also some test scripts in the `tools/testing/capsicum/` directory,
purely for local convenience when testing under user-mode Linux (`ARCH=um`).


UML Testing Setup
-----------------

Capsicum can be run and tested in a user-mode Linux build, for convenience and
speed of development iterations.  This section describes the setup procedure
for this method of testing.

Create a file to use as the disk for user-mode Linux (UML):

    # Create (sparse) empty file
    dd if=/dev/zero of=tools/testing/capsicum/test.img bs=1 count=0 seek=500GB
    # Make an ext3 filesystem in it
    mke2fs -t ext3 -F tools/testing/capsicum/test.img

Mount the new file system somewhere:

    sudo mount -o loop tools/testing/capsicum/test.img /mnt

Put an Ubuntu base system onto it:

    sudo debootstrap --arch=amd64 precise /mnt http://archive.ubuntu.com/ubuntu

Replace some key files:

    sudo cp /mnt/sbin/init /mnt/sbin/init.orig
    sudo cp tools/testing/capsicum/test-files/init /mnt/sbin/init
    sudo cp /mnt/etc/fstab /mnt/etc/fstab.orig
    sudo cp tools/testing/capsicum/test-files/fstab /mnt/etc/fstab
    sudo umount /mnt

Copy test binaries into the test directory:

    pushd ${CAPSICUM-TEST} && make && popd
    cp ${CAPSICUM-TEST}/capsicum-test tools/testing/capsicum/test-files/
    cp ${CAPSICUM-TEST}/mini-me tools/testing/capsicum/test-files/
    cp ${CAPSICUM-TEST}/mini-me.noexec tools/testing/capsicum/test-files/

Tests can then be run with the wrapper scripts:

    cd tools/testing/capsicum
    ./run-test ./capsicum-test

Under the covers the `init` script will mount `tools/testing/capsicum/test-files/`
as `/tests/` within the UML system, and will run tests from there.  The specific
test command to run is communicated into the UML instance as a `runtest=<cmd>` parameter
to the UML kernel (which the `init` script retrieves from `/proc/cmdline`).
