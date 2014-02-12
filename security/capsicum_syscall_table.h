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
#include <asm/unistd.h>
#include <asm/syscall.h>

/* TODO(drysdale): use a more general method for architecture-specific policing */
#if defined(CONFIG_X86) || defined(CONFIG_UML_X86)
#include <asm/prctl.h>
static int check_arch_prctl(unsigned long *args)
{
	return (args[0] & ~(ARCH_SET_FS|ARCH_GET_FS|ARCH_SET_GS|ARCH_GET_GS) ? -ECAPMODE : 0);
}
#else
static int check_arch_prctl(unsigned long *args)
{
	return -ECAPMODE;
}
#endif

static int check_kill(unsigned long *args)
{
	pid_t pid = args[0];
	return (pid == task_tgid_vnr(current)) ? 0 : -ECAPMODE;
}

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

enum capmode_result {
	CAPMODE_DENY = 0,
	CAPMODE_ALLOW,
	CAPMODE_SPECIAL
};
static unsigned char *syscalls_result;

static int __init init_syscalls_result(void)
{
	int i;
	syscalls_result = kcalloc(NR_syscalls, sizeof(unsigned char), GFP_KERNEL);
	if (!syscalls_result) {
		WARN_ON(1);
		return -ENOMEM;
	}
	for (i = 0; i < NR_syscalls; i++)
		syscalls_result[i] = CAPMODE_DENY;

	/* Syscalls whose arguments need to be examined */
	syscalls_result[__NR_arch_prctl] = CAPMODE_SPECIAL;
	syscalls_result[__NR_kill] = CAPMODE_SPECIAL;
	syscalls_result[__NR_mmap] = CAPMODE_SPECIAL;
	syscalls_result[__NR_openat] = CAPMODE_SPECIAL;
	syscalls_result[__NR_prctl] = CAPMODE_SPECIAL;

	/* Allowed syscalls */
	syscalls_result[__NR_accept] = CAPMODE_ALLOW;
	syscalls_result[__NR_accept4] = CAPMODE_ALLOW;
	syscalls_result[__NR_brk] = CAPMODE_ALLOW;
	syscalls_result[__NR_cap_getrights] = CAPMODE_ALLOW;
	syscalls_result[__NR_cap_new] = CAPMODE_ALLOW;
	syscalls_result[__NR_clock_getres] = CAPMODE_ALLOW;
	syscalls_result[__NR_clock_gettime] = CAPMODE_ALLOW;
	syscalls_result[__NR_clone] = CAPMODE_ALLOW;
	syscalls_result[__NR_close] = CAPMODE_ALLOW;
	syscalls_result[__NR_dup] = CAPMODE_ALLOW;
	syscalls_result[__NR_dup2] = CAPMODE_ALLOW;
	syscalls_result[__NR_dup3] = CAPMODE_ALLOW;
	syscalls_result[__NR_exit] = CAPMODE_ALLOW;
	syscalls_result[__NR_exit_group] = CAPMODE_ALLOW;
	syscalls_result[__NR_faccessat] = CAPMODE_ALLOW;
	syscalls_result[__NR_fchmod] = CAPMODE_ALLOW;
	syscalls_result[__NR_fchmodat] = CAPMODE_ALLOW;
	syscalls_result[__NR_fchown] = CAPMODE_ALLOW;
	syscalls_result[__NR_fchownat] = CAPMODE_ALLOW;
	syscalls_result[__NR_fcntl] = CAPMODE_ALLOW;
	syscalls_result[__NR_fdatasync] = CAPMODE_ALLOW;
	syscalls_result[__NR_fexecve] = CAPMODE_ALLOW;
	syscalls_result[__NR_fgetxattr] = CAPMODE_ALLOW;
	syscalls_result[__NR_finit_module] = CAPMODE_ALLOW;
	syscalls_result[__NR_flistxattr] = CAPMODE_ALLOW;
	syscalls_result[__NR_flock] = CAPMODE_ALLOW;
	syscalls_result[__NR_fork] = CAPMODE_ALLOW;
	syscalls_result[__NR_fremovexattr] = CAPMODE_ALLOW;
	syscalls_result[__NR_fsetxattr] = CAPMODE_ALLOW;
	syscalls_result[__NR_fstat] = CAPMODE_ALLOW;
	syscalls_result[__NR_fstatfs] = CAPMODE_ALLOW;
	syscalls_result[__NR_fsync] = CAPMODE_ALLOW;
	syscalls_result[__NR_ftruncate] = CAPMODE_ALLOW;
	syscalls_result[__NR_futimesat] = CAPMODE_ALLOW;
	syscalls_result[__NR_getdents] = CAPMODE_ALLOW;
	syscalls_result[__NR_getegid] = CAPMODE_ALLOW;
	syscalls_result[__NR_geteuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getgroups] = CAPMODE_ALLOW;
	syscalls_result[__NR_getitimer] = CAPMODE_ALLOW;
	syscalls_result[__NR_getpeername] = CAPMODE_ALLOW;
	syscalls_result[__NR_getpgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getpgrp] = CAPMODE_ALLOW;
	syscalls_result[__NR_getpid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getppid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getpriority] = CAPMODE_ALLOW;
	syscalls_result[__NR_getresgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getresuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getrlimit] = CAPMODE_ALLOW;
	syscalls_result[__NR_getrusage] = CAPMODE_ALLOW;
	syscalls_result[__NR_getsid] = CAPMODE_ALLOW;
	syscalls_result[__NR_getsockname] = CAPMODE_ALLOW;
	syscalls_result[__NR_getsockopt] = CAPMODE_ALLOW;
	syscalls_result[__NR_gettid] = CAPMODE_ALLOW;
	syscalls_result[__NR_gettimeofday] = CAPMODE_ALLOW;
	syscalls_result[__NR_getuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_ioctl] = CAPMODE_ALLOW;
	syscalls_result[__NR_linkat] = CAPMODE_ALLOW;
	syscalls_result[__NR_listen] = CAPMODE_ALLOW;
	syscalls_result[__NR_lseek] = CAPMODE_ALLOW;
	syscalls_result[__NR_madvise] = CAPMODE_ALLOW;
	syscalls_result[__NR_mincore] = CAPMODE_ALLOW;
	syscalls_result[__NR_mkdirat] = CAPMODE_ALLOW;
	syscalls_result[__NR_mknodat] = CAPMODE_ALLOW;
	syscalls_result[__NR_mlock] = CAPMODE_ALLOW;
	syscalls_result[__NR_mlockall] = CAPMODE_ALLOW;
	syscalls_result[__NR_mprotect] = CAPMODE_ALLOW;
	syscalls_result[__NR_mq_getsetattr] = CAPMODE_ALLOW;
	syscalls_result[__NR_mq_notify] = CAPMODE_ALLOW;
	syscalls_result[__NR_mq_timedreceive] = CAPMODE_ALLOW;
	syscalls_result[__NR_mq_timedsend] = CAPMODE_ALLOW;
	syscalls_result[__NR_msync] = CAPMODE_ALLOW;
	syscalls_result[__NR_munlock] = CAPMODE_ALLOW;
	syscalls_result[__NR_munlockall] = CAPMODE_ALLOW;
	syscalls_result[__NR_munmap] = CAPMODE_ALLOW;
	syscalls_result[__NR_nanosleep] = CAPMODE_ALLOW;
	syscalls_result[__NR_newfstatat] = CAPMODE_ALLOW;
	syscalls_result[__NR_pdfork] = CAPMODE_ALLOW;
	syscalls_result[__NR_pdgetpid] = CAPMODE_ALLOW;
	syscalls_result[__NR_pdkill] = CAPMODE_ALLOW;
	syscalls_result[__NR_pdwait4] = CAPMODE_ALLOW;
	syscalls_result[__NR_pipe] = CAPMODE_ALLOW;
	syscalls_result[__NR_pipe2] = CAPMODE_ALLOW;
	syscalls_result[__NR_poll] = CAPMODE_ALLOW;
	syscalls_result[__NR_ppoll] = CAPMODE_ALLOW;
	syscalls_result[__NR_pread64] = CAPMODE_ALLOW;
	syscalls_result[__NR_preadv] = CAPMODE_ALLOW;
	syscalls_result[__NR_pselect6] = CAPMODE_ALLOW;
	syscalls_result[__NR_pwrite64] = CAPMODE_ALLOW;
	syscalls_result[__NR_pwritev] = CAPMODE_ALLOW;
	syscalls_result[__NR_read] = CAPMODE_ALLOW;
	syscalls_result[__NR_readahead] = CAPMODE_ALLOW;
	syscalls_result[__NR_readlinkat] = CAPMODE_ALLOW;
	syscalls_result[__NR_readv] = CAPMODE_ALLOW;
	syscalls_result[__NR_recvfrom] = CAPMODE_ALLOW;
	syscalls_result[__NR_recvmmsg] = CAPMODE_ALLOW;
	syscalls_result[__NR_recvmsg] = CAPMODE_ALLOW;
	syscalls_result[__NR_renameat] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigaction] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigpending] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigprocmask] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigqueueinfo] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigreturn] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigsuspend] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_sigtimedwait] = CAPMODE_ALLOW;
	syscalls_result[__NR_rt_tgsigqueueinfo] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_get_priority_max] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_get_priority_min] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_getparam] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_getscheduler] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_rr_get_interval] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_setparam] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_setscheduler] = CAPMODE_ALLOW;
	syscalls_result[__NR_sched_yield] = CAPMODE_ALLOW;
	syscalls_result[__NR_select] = CAPMODE_ALLOW;
	syscalls_result[__NR_sendfile] = CAPMODE_ALLOW;
	syscalls_result[__NR_sendmmsg] = CAPMODE_ALLOW;
	syscalls_result[__NR_sendmsg] = CAPMODE_ALLOW;
	syscalls_result[__NR_sendto] = CAPMODE_ALLOW;
	syscalls_result[__NR_setfsgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setfsuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setitimer] = CAPMODE_ALLOW;
	syscalls_result[__NR_setpriority] = CAPMODE_ALLOW;
	syscalls_result[__NR_setregid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setresgid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setresuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setreuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setrlimit] = CAPMODE_ALLOW;
	syscalls_result[__NR_setsid] = CAPMODE_ALLOW;
	syscalls_result[__NR_setsockopt] = CAPMODE_ALLOW;
	syscalls_result[__NR_setuid] = CAPMODE_ALLOW;
	syscalls_result[__NR_shutdown] = CAPMODE_ALLOW;
	syscalls_result[__NR_sigaltstack] = CAPMODE_ALLOW;
	syscalls_result[__NR_socket] = CAPMODE_ALLOW;
	syscalls_result[__NR_socketpair] = CAPMODE_ALLOW;
	syscalls_result[__NR_symlinkat] = CAPMODE_ALLOW;
	syscalls_result[__NR_sync] = CAPMODE_ALLOW;
	syscalls_result[__NR_syncfs] = CAPMODE_ALLOW;
	syscalls_result[__NR_sync_file_range] = CAPMODE_ALLOW;
	syscalls_result[__NR_umask] = CAPMODE_ALLOW;
	syscalls_result[__NR_uname] = CAPMODE_ALLOW;
	syscalls_result[__NR_unlinkat] = CAPMODE_ALLOW;
	syscalls_result[__NR_unshare] = CAPMODE_ALLOW;
	syscalls_result[__NR_utimensat] = CAPMODE_ALLOW;
	syscalls_result[__NR_vfork] = CAPMODE_ALLOW;
	syscalls_result[__NR_vmsplice] = CAPMODE_ALLOW;
	syscalls_result[__NR_write] = CAPMODE_ALLOW;
	syscalls_result[__NR_writev] = CAPMODE_ALLOW;
	return 0;
}
arch_initcall(init_syscalls_result);

static int capsicum_run_syscall_table(int arch, int callnr, unsigned long *args)
{
	enum capmode_result rc;

	if (!syscalls_result || callnr >= NR_syscalls || callnr < 0)
		return -ECAPMODE;

	rc = syscalls_result[callnr];
	if (rc == CAPMODE_ALLOW)
		return 0;
	if (rc == CAPMODE_DENY)
		return -ECAPMODE;

	/* Special cases that depend on syscall arguments */
	switch (callnr) {
	case (__NR_arch_prctl):
		return check_arch_prctl(args);
	case (__NR_kill):
		return check_kill(args);
	case (__NR_mmap):
		return check_mmap(args);
	case (__NR_openat):
		return check_openat(args);
	case (__NR_prctl):
		return check_prctl(args);
	default:
		return -ECAPMODE;
	}
}
