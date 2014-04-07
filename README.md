Capsicum Object-Capabilities on Linux
=====================================

This repository holds the kernel code for the Linux version of the
[Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/)
security framework. Overall status of the Capsicum for Linux project is described at
[capsicum-linux.org](http://capsicum-linux.org/index.html).

Topic Branches
--------------

This repository includes four (per-version) topic branches, which hold
patchsets that apply cleanly on top of an upstream kernel version.  These
branches are **frequently rebased**, either because a new upstream release
candidate has become available, or because a fix to Capsicum code has been
folded into the patchset.

The `capsicum-hooks-<ver>` branch holds a patch set that can be applied on top
of the specified upstream kernel version, in order to provide the core Capsicum
object capability functionality.  This patch set breaks the functionality down
into individual chunks for ease of review and application; there are also
several commits that include independent pieces of function that are
potentially of interest on their own:

 - The first commits in the series add the `O_BENEATH` flag to `openat(2)`; this
   prevents the opening of paths with a leading '/' or that contain '..'.
 - A later commit in the series adds a `prctl(2)` operation to implicitly force
   the use of the `O_BENEATH` flag for all `openat(2)` operations for a task.
 - The penultimate commits in the series extend the `seccomp_data` structure to
   include the tid/tgid of the running process in the input data for any
   seccomp BPF programs; this allows the filter to police operations so that
   only the current thread or process can be targetted.
 - The final commit in the series exports additional headers and constants for
   system call numbers so that userspace tools can simultaneously access the
   different values for all x86 architectures.

The `procdesc-<ver>` branch holds a separate patch set that provides an
implementation of Capsicum's process descriptors, building on draft patches
from Josh Triplett in an incremental manner.  Note that this patchset is
completely independent from the `capsicum-hooks-<ver>` patchset.

The `misc-<ver>` branch holds a few independent fixes that are not required
for Capsicum functionality, but which should ideally be upstreamed at some point.

The `no-upstream-<ver>` branch holds local changes that should never be upstreamed;
they are held locally purely for the convenience of the Capsicum developers.


Development Branch
------------------

The `capsicum` branch is the main Capsicum development branch (and so may
contain in-progress code); the
[capsicum-test](https://github.com/google/capsicum-test) repository is normally
kept in sync with this branch.  This branch is never rebased; new upstream
kernel releases are merged into it as they become available.

Fixes to the Capsicum functionality on this branch will also be merged into the
appropriate topic branch.  As a result, a merge of the latest versions of the
four topic branches should normally be equivalent to the current status of the
`capsicum` branch.

![Capsicum branch structure](capsicum-branches.png)


Provenance
----------

This Capsicum implementation is based on:

 - the original Capsicum implementation in FreeBSD 9.x and 10.x,
   written by Robert Watson, Jonathan Anderson and Pawel Dawidek
 - an earlier
   [Linux kernel implementation](http://git.chromium.org/gitweb/?p=chromiumos/third_party/kernel-capsicum.git;a=shortlog;h=refs/heads/capsicum)
   written by Meredydd Luff in 2012.

The current functionality is based on the 4.2 upstream kernel.


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
    dd if=/dev/zero of=tools/testing/capsicum/test.img bs=1 count=0 seek=500MB
    # Make an ext3 filesystem in it
    mke2fs -t ext3 -F tools/testing/capsicum/test.img

Mount the new file system somewhere:

    sudo mount -o loop tools/testing/capsicum/test.img /mnt

Put an Ubuntu base system onto it:

    sudo debootstrap --arch=amd64 --include libsctp1 trusty /mnt http://archive.ubuntu.com/ubuntu

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
