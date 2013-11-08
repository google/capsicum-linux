/*
 * System call permission table for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */
#include <linux/audit.h>
#include <linux/mman.h>
#include <linux/poll.h>
#include <linux/prctl.h>
#include <asm/prctl.h>

static int check_mmap(struct capsicum_pending_syscall *pending,
		unsigned long *args)
{
	int prot = args[2];
	int flags = args[3];
	int fd = args[4];

	if (flags & MAP_ANONYMOUS)
		return 0;

	if (flags & ~(MAP_SHARED|MAP_PRIVATE|MAP_32BIT|MAP_FIXED|MAP_HUGETLB
			|MAP_NONBLOCK|MAP_NORESERVE|MAP_POPULATE|MAP_STACK))
		return -ECAPMODE;

	return capsicum_require_rights(pending, fd, CAP_MMAP)
		?: ((prot & PROT_READ) ? capsicum_require_rights(pending, fd, CAP_READ) : 0)
		?: ((prot & PROT_WRITE) ? capsicum_require_rights(pending, fd, CAP_WRITE) : 0)
		?: ((prot & PROT_EXEC) ? capsicum_require_rights(pending, fd, CAP_MAPEXEC) : 0);
}

static int check_openat(struct capsicum_pending_syscall *pending,
			unsigned long *args)
{
	return capsicum_require_rights(pending, args[0], CAP_LOOKUP
			| (args[2] & O_WRONLY ? CAP_WRITE : CAP_READ)
			| (args[2] & O_RDWR ? CAP_READ|CAP_WRITE : 0)
			| (args[2] & O_CREAT ? CAP_WRITE : 0)
			| (args[2] & O_EXCL ? CAP_WRITE : 0)
			| (args[2] & O_TRUNC ? CAP_WRITE : 0))
		?: (args[2] & ~(O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC) ? -ECAPMODE : 0);
}

static int check_prctl(struct capsicum_pending_syscall *pending,
		unsigned long *args)
{
	/* Allow through PR_GET_* calls */
	switch (args[0]) {
	case PR_CAPBSET_READ:
	case PR_CAPBSET_DROP:
	case PR_GET_DUMPABLE:
	case PR_GET_ENDIAN:
	case PR_GET_FPEMU:
	case PR_GET_KEEPCAPS:
	case PR_GET_NAME:
	case PR_GET_NO_NEW_PRIVS:
	case PR_GET_PDEATHSIG:
	case PR_GET_SECCOMP:
	case PR_GET_SECUREBITS:
	case PR_GET_TIMERSLACK:
	case PR_GET_TIMING:
	case PR_GET_TSC:
	case PR_GET_UNALIGN:
	case PR_MCE_KILL_GET:
		return 0;
	default:
		return -ECAPMODE;
	}
}

static int check_select(struct capsicum_pending_syscall *pending,
			unsigned long *args)
{
	int n;
	int ret = 0;
	void *bits;
	unsigned int size;
	/* Allocate small arguments on the stack to save memory and be faster */
	long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];
	unsigned long *inp, *outp, *exp;
	int ii, jj;

	/*
	 * We need 3 bitmaps (in/out/ex for incoming only), since we used fdset
	 * we need to allocate memory in units of long-words.
	 */
	n = args[0];
	size = FDS_BYTES(n);
	bits = stack_fds;
	if (size > sizeof(stack_fds) / 3) {
		/* Not enough space in on-stack array; must use kmalloc */
		ret = -ENOMEM;
		bits = kmalloc(3 * size, GFP_KERNEL);
		if (!bits)
			goto out_nofds;
	}
	inp = (unsigned long*)bits;
	outp = (unsigned long *)(bits + size);
	exp = (unsigned long *)(bits + 2*size);

	if ((ret = get_fd_set(n, (fd_set __user *)args[1], inp)) ||
	    (ret = get_fd_set(n, (fd_set __user *)args[2], outp)) ||
	    (ret = get_fd_set(n, (fd_set __user *)args[3], exp)))
		goto out;

	/*
	 * Also resize the internals of the capsicum_pending_syscall so there is
	 * enough space for all the fd/struct files involved.  This may fail, which
	 * will trigger an -ENOMEM failure from capsicum_require_rights() below.
	 */
	capsicum_realloc_pending_syscall(pending, n);

	/* Check that each of the file descriptors involved has CAP_POLL_EVENT. */
	for (ii = 0; ii < n; ) {
		unsigned long in, out, ex;
		unsigned long all_bits, bit = 1;
		in = *inp++; out = *outp++; ex = *exp++;
		all_bits = in | out | ex;
		if (all_bits == 0) {
			ii += BITS_PER_LONG;
			continue;
		}
		for (jj = 0; jj < BITS_PER_LONG; ++jj, ++ii, bit <<= 1) {
			if (ii >= n)
				break;
			if (!(bit & all_bits))
				continue;
			ret = capsicum_require_rights(pending, ii, CAP_POLL_EVENT);
			if (ret)
				goto out;
		}
	}
out:
	if (bits != stack_fds)
		kfree(bits);
out_nofds:
	return ret;
}

static int capsicum_run_syscall_table(struct capsicum_pending_syscall *pending,
				int arch, int callnr, unsigned long *args)
{
	if (arch != AUDIT_ARCH_X86_64)
		return -ECAPMODE;

	switch (callnr) {
	case (__NR_accept): return capsicum_require_rights(pending, args[0], CAP_ACCEPT);
	case (__NR_accept4): return capsicum_require_rights(pending, args[0], CAP_ACCEPT);
	case (__NR_arch_prctl):
		return (args[0] & ~(ARCH_SET_FS|ARCH_GET_FS|ARCH_SET_GS|ARCH_GET_GS) ? -ECAPMODE : 0);
	case (__NR_brk): return 0;
	case (__NR_cap_getrights): return 0;
	case (__NR_cap_new): return 0;
	case (__NR_clock_getres): return 0;
	case (__NR_clock_gettime): return 0;
	case (__NR_clone): return 0;
	case (__NR_close): return 0;
	case (__NR_dup): return 0;
	case (__NR_dup2): return 0;
	case (__NR_dup3): return 0;
	case (__NR_exit): return 0;
	case (__NR_exit_group): return 0;
	case (__NR_faccessat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP);
	case (__NR_fchmod): return capsicum_require_rights(pending, args[0], CAP_FCHMOD);
	case (__NR_fchmodat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_FCHMOD);
	case (__NR_fchown): return capsicum_require_rights(pending, args[0], CAP_FCHOWN);
	case (__NR_fchownat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_FCHOWN);
	case (__NR_fcntl): return capsicum_require_rights(pending, args[0], CAP_FCNTL);
	case (__NR_fdatasync): return capsicum_require_rights(pending, args[0], CAP_FSYNC);
	case (__NR_fexecve): return capsicum_require_rights(pending, args[0], CAP_FEXECVE);
	case (__NR_fgetxattr): return capsicum_require_rights(pending, args[0], CAP_EXTATTR_GET);
	case (__NR_finit_module): return capsicum_require_rights(pending, args[0], CAP_FEXECVE);
	case (__NR_flistxattr): return capsicum_require_rights(pending, args[0], CAP_EXTATTR_LIST);
	case (__NR_flock): return capsicum_require_rights(pending, args[0], CAP_FLOCK);
	case (__NR_fork): return 0;
	case (__NR_fremovexattr): return capsicum_require_rights(pending, args[0], CAP_EXTATTR_DELETE);
	case (__NR_fsetxattr): return capsicum_require_rights(pending, args[0], CAP_EXTATTR_SET);
	case (__NR_fstat): return capsicum_require_rights(pending, args[0], CAP_FSTAT);
	case (__NR_fstatfs): return capsicum_require_rights(pending, args[0], CAP_FSTATFS);
	case (__NR_fsync): return capsicum_require_rights(pending, args[0], CAP_FSYNC);
	case (__NR_ftruncate): return capsicum_require_rights(pending, args[0], CAP_FTRUNCATE);
	case (__NR_futimesat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_FUTIMES);
	case (__NR_getdents): return capsicum_require_rights(pending, args[0], CAP_READ|CAP_SEEK);
	case (__NR_getegid): return 0;
	case (__NR_geteuid): return 0;
	case (__NR_getgid): return 0;
	case (__NR_getgroups): return 0;
	case (__NR_getitimer): return 0;
	case (__NR_getpeername): return capsicum_require_rights(pending, args[0], CAP_GETPEERNAME);
	case (__NR_getpgid): return 0;
	case (__NR_getpgrp): return 0;
	case (__NR_getpid): return 0;
	case (__NR_getppid): return 0;
	case (__NR_getpriority): return 0;
	case (__NR_getresgid): return 0;
	case (__NR_getresuid): return 0;
	case (__NR_getrlimit): return 0;
	case (__NR_getrusage): return 0;
	case (__NR_getsid): return 0;
	case (__NR_getsockname): return capsicum_require_rights(pending, args[0], CAP_GETSOCKNAME);
	case (__NR_getsockopt): return capsicum_require_rights(pending, args[0], CAP_GETSOCKOPT);
	case (__NR_gettimeofday): return 0;
	case (__NR_getuid): return 0;
	case (__NR_ioctl): return capsicum_require_rights(pending, args[0], CAP_IOCTL);
	case (__NR_linkat):
		return capsicum_require_rights(pending, args[0], CAP_LOOKUP)
			?: capsicum_require_rights(pending, args[2], CAP_LOOKUP|CAP_CREATE);
	case (__NR_listen): return capsicum_require_rights(pending, args[0], CAP_LISTEN);
	case (__NR_lseek): return capsicum_require_rights(pending, args[0], CAP_SEEK);
	case (__NR_madvise): return 0;
	case (__NR_mincore): return 0;
	case (__NR_mkdirat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_MKDIR);
	case (__NR_mknodat): return capsicum_require_rights(pending, args[0], CAP_MKFIFO);
	case (__NR_mlock): return 0;
	case (__NR_mlockall): return 0;
	case (__NR_mmap): return check_mmap(pending, args);
	case (__NR_mprotect): return 0;
	case (__NR_msync): return 0;
	case (__NR_munlock): return 0;
	case (__NR_munlockall): return 0;
	case (__NR_munmap): return 0;
	case (__NR_nanosleep): return 0;
	case (__NR_newfstatat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_FSTAT);
	case (__NR_openat): return check_openat(pending, args);
	case (__NR_pdfork): return 0;
	case (__NR_pdgetpid): return capsicum_require_rights(pending, args[0], CAP_PDGETPID);
	case (__NR_pdkill): return capsicum_require_rights(pending, args[0], CAP_PDKILL);
	case (__NR_pdwait4): return capsicum_require_rights(pending, args[0], CAP_PDWAIT);
	case (__NR_pipe): return 0;
	case (__NR_pipe2): return 0;
	case (__NR_prctl): return check_prctl(pending, args);
	case (__NR_pread64): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_preadv): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_pwrite64): return capsicum_require_rights(pending, args[0], CAP_WRITE);
	case (__NR_pwritev): return capsicum_require_rights(pending, args[0], CAP_WRITE);
	case (__NR_read): return capsicum_require_rights(pending, args[0], CAP_READ|CAP_SEEK);
	case (__NR_readahead): return capsicum_require_rights(pending, args[0], CAP_READ|CAP_SEEK);
	case (__NR_readlinkat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_READ);
	case (__NR_readv): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_recvfrom): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_recvmmsg): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_recvmsg): return capsicum_require_rights(pending, args[0], CAP_READ);
	case (__NR_renameat):
		return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_DELETE)
			?: capsicum_require_rights(pending, args[2], CAP_LOOKUP|CAP_CREATE);
	case (__NR_rt_sigaction): return 0;
	case (__NR_sched_get_priority_max): return 0;
	case (__NR_sched_get_priority_min): return 0;
	case (__NR_sched_getparam): return 0;
	case (__NR_sched_getscheduler): return 0;
	case (__NR_sched_rr_get_interval): return 0;
	case (__NR_sched_setparam): return 0;
	case (__NR_sched_setscheduler): return 0;
	case (__NR_sched_yield): return 0;
	case (__NR_select): return check_select(pending, args);
	case (__NR_sendfile):
		return capsicum_require_rights(pending, args[0], CAP_READ)
			?: capsicum_require_rights(pending, args[1], CAP_WRITE);
	case (__NR_sendmmsg): return capsicum_require_rights(pending, args[0], CAP_WRITE | CAP_CONNECT);
	case (__NR_sendmsg): return capsicum_require_rights(pending, args[0], CAP_WRITE | CAP_CONNECT);
	case (__NR_sendto):
		return capsicum_require_rights(pending, args[0], CAP_WRITE | (((void *)args[4] != NULL) ? CAP_CONNECT : 0));
	case (__NR_setfsgid): return 0;
	case (__NR_setfsuid): return 0;
	case (__NR_setgid): return 0;
	case (__NR_setitimer): return 0;
	case (__NR_setpriority): return 0;
	case (__NR_setregid): return 0;
	case (__NR_setresgid): return 0;
	case (__NR_setresuid): return 0;
	case (__NR_setreuid): return 0;
	case (__NR_setrlimit): return 0;
	case (__NR_setsid): return 0;
	case (__NR_setsockopt): return capsicum_require_rights(pending, args[0], CAP_SETSOCKOPT);
	case (__NR_setuid): return 0;
	case (__NR_shutdown): return capsicum_require_rights(pending, args[0], CAP_SHUTDOWN);
	case (__NR_sigaltstack): return 0;
	case (__NR_socket): return 0;
	case (__NR_socketpair): return 0;
	case (__NR_symlinkat): return capsicum_require_rights(pending, args[1], CAP_LOOKUP|CAP_CREATE);
	case (__NR_sync): return 0;
	case (__NR_syncfs): return capsicum_require_rights(pending, args[0], CAP_FSYNC);
	case (__NR_sync_file_range): return capsicum_require_rights(pending, args[0], CAP_FSYNC);
	case (__NR_umask): return 0;
	case (__NR_uname): return 0;
	case (__NR_unlinkat): return capsicum_require_rights(pending, args[0], CAP_LOOKUP|CAP_DELETE);
	case (__NR_utimensat):
		return capsicum_require_rights(pending, args[0], CAP_FUTIMES | (((void *)args[1] != NULL) ? CAP_LOOKUP : 0));
	case (__NR_vfork): return 0;
	case (__NR_vmsplice): return capsicum_require_rights(pending, args[0], CAP_WRITE);
	case (__NR_write): return capsicum_require_rights(pending, args[0], CAP_WRITE|CAP_SEEK);
	case (__NR_writev): return capsicum_require_rights(pending, args[0], CAP_WRITE);
	default: return -ECAPMODE;
	}
}
