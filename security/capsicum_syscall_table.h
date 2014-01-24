/*
 * System call permission table for Capsicum, a capability framework for UNIX.
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
#include <linux/socket.h>
#include <net/compat.h>
#include <net/scm.h>
#include <net/sock.h>
#include <asm/prctl.h>

static int check_mmap(unsigned long *args)
{
	int flags = args[3];

	if (flags & MAP_ANONYMOUS)
		return 0;

	if (flags & ~(MAP_SHARED|MAP_PRIVATE|MAP_32BIT|MAP_FIXED|MAP_HUGETLB
			|MAP_NONBLOCK|MAP_NORESERVE|MAP_POPULATE|MAP_STACK))
		return -ECAPMODE;

	return 0;
}

static int check_openat(unsigned long *args)
{
	int fd = args[0];
	int flags = args[2];

	if (fd == AT_FDCWD)
		return -ECAPMODE;
	return (flags & ~(O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC) ? -ECAPMODE : 0);
}

static int check_prctl(unsigned long *args)
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

static int capsicum_run_syscall_table(int arch, int callnr, unsigned long *args)
{
	if (arch != AUDIT_ARCH_X86_64)
		return -ECAPMODE;

	switch (callnr) {
	case (__NR_arch_prctl):
		return (args[0] & ~(ARCH_SET_FS|ARCH_GET_FS|ARCH_SET_GS|ARCH_GET_GS) ? -ECAPMODE : 0);
	case (__NR_mmap):
		return check_mmap(args);
	case (__NR_openat):
		return check_openat(args);
	case (__NR_prctl):
		return check_prctl(args);

	case (__NR_accept):
	case (__NR_accept4):
	case (__NR_brk):
	case (__NR_cap_getrights):
	case (__NR_cap_new):
	case (__NR_clock_getres):
	case (__NR_clock_gettime):
	case (__NR_clone):
	case (__NR_close):
	case (__NR_dup):
	case (__NR_dup2):
	case (__NR_dup3):
	case (__NR_exit):
	case (__NR_exit_group):
	case (__NR_faccessat):
	case (__NR_fchmod):
	case (__NR_fchmodat):
	case (__NR_fchown):
	case (__NR_fchownat):
	case (__NR_fcntl):
	case (__NR_fdatasync):
	case (__NR_fexecve):
	case (__NR_fgetxattr):
	case (__NR_finit_module):
	case (__NR_flistxattr):
	case (__NR_flock):
	case (__NR_fork):
	case (__NR_fremovexattr):
	case (__NR_fsetxattr):
	case (__NR_fstat):
	case (__NR_fstatfs):
	case (__NR_fsync):
	case (__NR_ftruncate):
	case (__NR_futimesat):
	case (__NR_getdents):
	case (__NR_getegid):
	case (__NR_geteuid):
	case (__NR_getgid):
	case (__NR_getgroups):
	case (__NR_getitimer):
	case (__NR_getpeername):
	case (__NR_getpgid):
	case (__NR_getpgrp):
	case (__NR_getpid):
	case (__NR_getppid):
	case (__NR_getpriority):
	case (__NR_getresgid):
	case (__NR_getresuid):
	case (__NR_getrlimit):
	case (__NR_getrusage):
	case (__NR_getsid):
	case (__NR_getsockname):
	case (__NR_getsockopt):
	case (__NR_gettid):
	case (__NR_gettimeofday):
	case (__NR_getuid):
	case (__NR_ioctl):
	case (__NR_linkat):
	case (__NR_listen):
	case (__NR_lseek):
	case (__NR_madvise):
	case (__NR_mincore):
	case (__NR_mkdirat):
	case (__NR_mknodat):
	case (__NR_mlock):
	case (__NR_mlockall):
	case (__NR_mprotect):
	case (__NR_mq_getsetattr):
	case (__NR_mq_notify):
	case (__NR_mq_timedreceive):
	case (__NR_mq_timedsend):
	case (__NR_msync):
	case (__NR_munlock):
	case (__NR_munlockall):
	case (__NR_munmap):
	case (__NR_nanosleep):
	case (__NR_newfstatat):
	case (__NR_pdfork):
	case (__NR_pdgetpid):
	case (__NR_pdkill):
	case (__NR_pdwait4):
	case (__NR_pipe):
	case (__NR_pipe2):
	case (__NR_poll):
	case (__NR_ppoll):
	case (__NR_pread64):
	case (__NR_preadv):
	case (__NR_pselect6):
	case (__NR_pwrite64):
	case (__NR_pwritev):
	case (__NR_read):
	case (__NR_readahead):
	case (__NR_readlinkat):
	case (__NR_readv):
	case (__NR_recvfrom):
	case (__NR_recvmmsg):
	case (__NR_recvmsg):
	case (__NR_renameat):
	case (__NR_rt_sigaction):
	case (__NR_rt_sigpending):
	case (__NR_rt_sigprocmask):
	case (__NR_rt_sigqueueinfo):
	case (__NR_rt_sigreturn):
	case (__NR_rt_sigsuspend):
	case (__NR_rt_sigtimedwait):
	case (__NR_rt_tgsigqueueinfo):
	case (__NR_sched_get_priority_max):
	case (__NR_sched_get_priority_min):
	case (__NR_sched_getparam):
	case (__NR_sched_getscheduler):
	case (__NR_sched_rr_get_interval):
	case (__NR_sched_setparam):
	case (__NR_sched_setscheduler):
	case (__NR_sched_yield):
	case (__NR_select):
	case (__NR_sendfile):
	case (__NR_sendmmsg):
	case (__NR_sendmsg):
	case (__NR_sendto):
	case (__NR_setfsgid):
	case (__NR_setfsuid):
	case (__NR_setgid):
	case (__NR_setitimer):
	case (__NR_setpriority):
	case (__NR_setregid):
	case (__NR_setresgid):
	case (__NR_setresuid):
	case (__NR_setreuid):
	case (__NR_setrlimit):
	case (__NR_setsid):
	case (__NR_setsockopt):
	case (__NR_setuid):
	case (__NR_shutdown):
	case (__NR_sigaltstack):
	case (__NR_socket):
	case (__NR_socketpair):
	case (__NR_symlinkat):
	case (__NR_sync):
	case (__NR_syncfs):
	case (__NR_sync_file_range):
	case (__NR_umask):
	case (__NR_uname):
	case (__NR_unlinkat):
	case (__NR_unshare):
	case (__NR_utimensat):
	case (__NR_vfork):
	case (__NR_vmsplice):
	case (__NR_write):
	case (__NR_writev):
		return 0;
	default:
		return -ECAPMODE;
	}
}
