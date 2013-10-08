Capsicum Object-Capabilities on Linux
=====================================

This repository is used for the development of
[Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/) object
capabilities in the Linux kernel.

This functionality is based on:

 - the original Capsicum implementation in FreeBSD 9.x,
   written by Robert Watson and Jonathan Anderson.
 - the
   [Linux kernel implementation](http://git.chromium.org/gitweb/?p=chromiumos/third_party/kernel-capsicum.git;a=shortlog;h=refs/heads/capsicum)
   written by Meredydd Luff in 2012.

The current functionality is based on the 3.11.1 upstream kernel.

Functionality Overview
----------------------

Capsicum introduces a new kind of file descriptor, a *capability*, which has a
limited set of rights associated with it.  Operations on a capability that are
not allowed by the associated rights are rejected (with `ENOTCAPABLE`).  New
capabilities can only have a subset of the rights of an existing file
descriptor/capability.

Capsicum also introduces *capability mode*, which disables (with `ECAPMODE`)
all syscalls that access any kind of global namespace.

Taken together, these features allow userspace code to effectively sandbox
itself, by:

 - creating capabilities (with limited rights) to files and sockets that are
   definitely needed by the process
 - closing all other file descriptors
 - entering capability mode (which means that new, non-capability, file
   descriptors can't be opened.

As process management normally involves a global namespace (that of `pid_t`
values), Capsicum also introduces a *process descriptor* and related syscalls,
which allows processes to be manipulated as another kind of file descriptor.

Building
--------

Capsicum support is currently included for x86_64 and user-mode Linux.  The
configuration parameters that need to be enabled are:

 - `CONFIG_64BIT`: Capsicum support is currently only implemented for 64 bit mode.
 - `CONFIG_SECURITY`: enable Linux Security Module (LSM) support.
 - `CONFIG_SECURITY_PATH`: enable LSM hooks for path operations
 - `CONFIG_SECURITY_CAPSICUM`: enable the Capsicum LSM.
 - `CONFIG_PROCDESC`: enable Capsicum process-descriptor functionality.

User-mode Linux is used for Capsicum testing, and requires the following
additional configuration parameters:

- `CONFIG_DEBUG_FS`: enable debug filesystem.


Testing
-------

The capsicum-linux currently includes tests and test scripts in the
`tools/testing/capsicum_tests/` directory (although the tests themselves are
being migrated to the separate
[capsicum-test](https://github.com/google/capsicum-test) repository).

These test scripts currently expect specific build configurations (replacing the
`-j 5` flag with an appropriate parallelization factor for the local machine):

 - For user-mode Linux, the kernel should be built with ``make -j 5 ARCH=um
   O=`pwd`/build/ linux`` (i.e. the old-style `linux` target is required, and the
   output tree is expect to be under the `build/` subdirectory).

 - For native Linux (including VMs), the kernel should be built with
   ``make -j 5 O=`pwd`/build-native``
