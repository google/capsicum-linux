/*
 * System call permission table for Capsicum, a capability framework for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Copyright (C) 2013-2014 Google, Inc.
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
#include <linux/seccomp.h>
#include <net/compat.h>
#include <net/scm.h>
#include <net/sock.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

#ifdef CONFIG_SECURITY_CAPSICUM

/* TODO(drysdale): use a more general method for arch-specific policing */
#ifdef __NR_arch_prctl
#if defined(CONFIG_X86) || defined(CONFIG_UML_X86)
#include <asm/prctl.h>
static int check_arch_prctl(unsigned long *args)
{
	int code = args[0];
	if (code == ARCH_GET_FS || code == ARCH_GET_GS ||
	    code == ARCH_SET_FS || code == ARCH_SET_GS)
		return SECCOMP_RET_ALLOW;
	else
		return SECCOMP_RET_ERRNO|ECAPMODE;
}
#else
static int check_arch_prctl(unsigned long *args)
{
	return SECCOMP_RET_ERRNO|ECAPMODE;
}
#endif
#endif

static int check_kill(unsigned long *args)
{
	pid_t pid = args[0];
	return (pid == task_tgid_vnr(current))
	       ? SECCOMP_RET_ALLOW : SECCOMP_RET_ERRNO|ECAPMODE;
}

static int check_mmap(unsigned long *args)
{
	static const int allowed_flags = (MAP_NORESERVE|MAP_POPULATE|
					  MAP_NONBLOCK|MAP_HUGETLB|MAP_STACK|
#ifdef MAP_32BIT
					  MAP_32BIT|
#endif
					  MAP_SHARED|MAP_PRIVATE|MAP_FIXED);
	int flags = args[3];

	if (flags & MAP_ANONYMOUS)
		return SECCOMP_RET_ALLOW;

	if (flags & ~allowed_flags)
		return SECCOMP_RET_ERRNO|ECAPMODE;

	return SECCOMP_RET_ALLOW;
}

static int check_openat(unsigned long *args)
{
	int fd = args[0];
	int flags = args[2];

	if (fd == AT_FDCWD)
		return SECCOMP_RET_ERRNO|ECAPMODE;
	return (flags & ~(O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|
			  FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|
			  O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC))
		? SECCOMP_RET_ERRNO|ECAPMODE : SECCOMP_RET_ALLOW;
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
		return SECCOMP_RET_ALLOW;
	default:
		return SECCOMP_RET_ERRNO|ECAPMODE;
	}
}

static int check_tgkill(unsigned long *args)
{
	pid_t tgid = args[0];
	return (tgid == task_tgid_vnr(current))
	       ? SECCOMP_RET_ALLOW : SECCOMP_RET_ERRNO|ECAPMODE;
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
	syscalls_result = kcalloc(NR_syscalls, sizeof(unsigned char),
				  GFP_KERNEL);
	if (!syscalls_result) {
		WARN_ON(1);
		return -ENOMEM;
	}
	for (i = 0; i < NR_syscalls; i++)
		syscalls_result[i] = CAPMODE_DENY;

	/* Syscalls whose arguments need to be examined */
#ifdef __NR_arch_prctl
	syscalls_result[__NR_arch_prctl] = CAPMODE_SPECIAL;
#endif
#ifdef __NR_kill
	syscalls_result[__NR_kill] = CAPMODE_SPECIAL;
#endif
#ifdef __NR_mmap
	syscalls_result[__NR_mmap] = CAPMODE_SPECIAL;
#endif
#ifdef __NR_openat
	syscalls_result[__NR_openat] = CAPMODE_SPECIAL;
#endif
#ifdef __NR_prctl
	syscalls_result[__NR_prctl] = CAPMODE_SPECIAL;
#endif
#ifdef __NR_tgkill
	syscalls_result[__NR_tgkill] = CAPMODE_SPECIAL;
#endif

	/* Allowed syscalls */
#ifdef __NR_accept
	syscalls_result[__NR_accept] = CAPMODE_ALLOW;
#endif
#ifdef __NR_accept4
	syscalls_result[__NR_accept4] = CAPMODE_ALLOW;
#endif
#ifdef __NR_brk
	syscalls_result[__NR_brk] = CAPMODE_ALLOW;
#endif
#ifdef __NR_cap_rights_get
	syscalls_result[__NR_cap_rights_get] = CAPMODE_ALLOW;
#endif
#ifdef __NR_cap_rights_limit
	syscalls_result[__NR_cap_rights_limit] = CAPMODE_ALLOW;
#endif
#ifdef __NR_clock_getres
	syscalls_result[__NR_clock_getres] = CAPMODE_ALLOW;
#endif
#ifdef __NR_clock_gettime
	syscalls_result[__NR_clock_gettime] = CAPMODE_ALLOW;
#endif
#ifdef __NR_clone
	syscalls_result[__NR_clone] = CAPMODE_ALLOW;
#endif
#ifdef __NR_close
	syscalls_result[__NR_close] = CAPMODE_ALLOW;
#endif
#ifdef __NR_dup
	syscalls_result[__NR_dup] = CAPMODE_ALLOW;
#endif
#ifdef __NR_dup2
	syscalls_result[__NR_dup2] = CAPMODE_ALLOW;
#endif
#ifdef __NR_dup3
	syscalls_result[__NR_dup3] = CAPMODE_ALLOW;
#endif
#ifdef __NR_execveat
	syscalls_result[__NR_execveat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_exit
	syscalls_result[__NR_exit] = CAPMODE_ALLOW;
#endif
#ifdef __NR_exit_group
	syscalls_result[__NR_exit_group] = CAPMODE_ALLOW;
#endif
#ifdef __NR_faccessat
	syscalls_result[__NR_faccessat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fchmod
	syscalls_result[__NR_fchmod] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fchmodat
	syscalls_result[__NR_fchmodat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fchown
	syscalls_result[__NR_fchown] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fchownat
	syscalls_result[__NR_fchownat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fcntl
	syscalls_result[__NR_fcntl] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fdatasync
	syscalls_result[__NR_fdatasync] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fgetxattr
	syscalls_result[__NR_fgetxattr] = CAPMODE_ALLOW;
#endif
#ifdef __NR_finit_module
	syscalls_result[__NR_finit_module] = CAPMODE_ALLOW;
#endif
#ifdef __NR_flistxattr
	syscalls_result[__NR_flistxattr] = CAPMODE_ALLOW;
#endif
#ifdef __NR_flock
	syscalls_result[__NR_flock] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fork
	syscalls_result[__NR_fork] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fremovexattr
	syscalls_result[__NR_fremovexattr] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fsetxattr
	syscalls_result[__NR_fsetxattr] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fstat
	syscalls_result[__NR_fstat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fstatfs
	syscalls_result[__NR_fstatfs] = CAPMODE_ALLOW;
#endif
#ifdef __NR_fsync
	syscalls_result[__NR_fsync] = CAPMODE_ALLOW;
#endif
#ifdef __NR_ftruncate
	syscalls_result[__NR_ftruncate] = CAPMODE_ALLOW;
#endif
#ifdef __NR_futimesat
	syscalls_result[__NR_futimesat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getdents
	syscalls_result[__NR_getdents] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getegid
	syscalls_result[__NR_getegid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_geteuid
	syscalls_result[__NR_geteuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getgid
	syscalls_result[__NR_getgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getgroups
	syscalls_result[__NR_getgroups] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getitimer
	syscalls_result[__NR_getitimer] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getpeername
	syscalls_result[__NR_getpeername] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getpgid
	syscalls_result[__NR_getpgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getpgrp
	syscalls_result[__NR_getpgrp] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getpid
	syscalls_result[__NR_getpid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getppid
	syscalls_result[__NR_getppid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getpriority
	syscalls_result[__NR_getpriority] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getresgid
	syscalls_result[__NR_getresgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getresuid
	syscalls_result[__NR_getresuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getrlimit
	syscalls_result[__NR_getrlimit] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getrusage
	syscalls_result[__NR_getrusage] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getsid
	syscalls_result[__NR_getsid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getsockname
	syscalls_result[__NR_getsockname] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getsockopt
	syscalls_result[__NR_getsockopt] = CAPMODE_ALLOW;
#endif
#ifdef __NR_gettid
	syscalls_result[__NR_gettid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_gettimeofday
	syscalls_result[__NR_gettimeofday] = CAPMODE_ALLOW;
#endif
#ifdef __NR_getuid
	syscalls_result[__NR_getuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_ioctl
	syscalls_result[__NR_ioctl] = CAPMODE_ALLOW;
#endif
#ifdef __NR_linkat
	syscalls_result[__NR_linkat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_listen
	syscalls_result[__NR_listen] = CAPMODE_ALLOW;
#endif
#ifdef __NR_lseek
	syscalls_result[__NR_lseek] = CAPMODE_ALLOW;
#endif
#ifdef __NR_madvise
	syscalls_result[__NR_madvise] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mincore
	syscalls_result[__NR_mincore] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mkdirat
	syscalls_result[__NR_mkdirat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mknodat
	syscalls_result[__NR_mknodat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mlock
	syscalls_result[__NR_mlock] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mlockall
	syscalls_result[__NR_mlockall] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mprotect
	syscalls_result[__NR_mprotect] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mq_getsetattr
	syscalls_result[__NR_mq_getsetattr] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mq_notify
	syscalls_result[__NR_mq_notify] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mq_timedreceive
	syscalls_result[__NR_mq_timedreceive] = CAPMODE_ALLOW;
#endif
#ifdef __NR_mq_timedsend
	syscalls_result[__NR_mq_timedsend] = CAPMODE_ALLOW;
#endif
#ifdef __NR_msync
	syscalls_result[__NR_msync] = CAPMODE_ALLOW;
#endif
#ifdef __NR_munlock
	syscalls_result[__NR_munlock] = CAPMODE_ALLOW;
#endif
#ifdef __NR_munlockall
	syscalls_result[__NR_munlockall] = CAPMODE_ALLOW;
#endif
#ifdef __NR_munmap
	syscalls_result[__NR_munmap] = CAPMODE_ALLOW;
#endif
#ifdef __NR_nanosleep
	syscalls_result[__NR_nanosleep] = CAPMODE_ALLOW;
#endif
#ifdef __NR_newfstatat
	syscalls_result[__NR_newfstatat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pdfork
	syscalls_result[__NR_pdfork] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pdgetpid
	syscalls_result[__NR_pdgetpid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pdkill
	syscalls_result[__NR_pdkill] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pdwait4
	syscalls_result[__NR_pdwait4] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pipe
	syscalls_result[__NR_pipe] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pipe2
	syscalls_result[__NR_pipe2] = CAPMODE_ALLOW;
#endif
#ifdef __NR_poll
	syscalls_result[__NR_poll] = CAPMODE_ALLOW;
#endif
#ifdef __NR_ppoll
	syscalls_result[__NR_ppoll] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pread64
	syscalls_result[__NR_pread64] = CAPMODE_ALLOW;
#endif
#ifdef __NR_preadv
	syscalls_result[__NR_preadv] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pselect6
	syscalls_result[__NR_pselect6] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pwrite64
	syscalls_result[__NR_pwrite64] = CAPMODE_ALLOW;
#endif
#ifdef __NR_pwritev
	syscalls_result[__NR_pwritev] = CAPMODE_ALLOW;
#endif
#ifdef __NR_read
	syscalls_result[__NR_read] = CAPMODE_ALLOW;
#endif
#ifdef __NR_readahead
	syscalls_result[__NR_readahead] = CAPMODE_ALLOW;
#endif
#ifdef __NR_readlinkat
	syscalls_result[__NR_readlinkat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_readv
	syscalls_result[__NR_readv] = CAPMODE_ALLOW;
#endif
#ifdef __NR_recvfrom
	syscalls_result[__NR_recvfrom] = CAPMODE_ALLOW;
#endif
#ifdef __NR_recvmmsg
	syscalls_result[__NR_recvmmsg] = CAPMODE_ALLOW;
#endif
#ifdef __NR_recvmsg
	syscalls_result[__NR_recvmsg] = CAPMODE_ALLOW;
#endif
#ifdef __NR_renameat
	syscalls_result[__NR_renameat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigaction
	syscalls_result[__NR_rt_sigaction] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigpending
	syscalls_result[__NR_rt_sigpending] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigprocmask
	syscalls_result[__NR_rt_sigprocmask] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigqueueinfo
	syscalls_result[__NR_rt_sigqueueinfo] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigreturn
	syscalls_result[__NR_rt_sigreturn] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigsuspend
	syscalls_result[__NR_rt_sigsuspend] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_sigtimedwait
	syscalls_result[__NR_rt_sigtimedwait] = CAPMODE_ALLOW;
#endif
#ifdef __NR_rt_tgsigqueueinfo
	syscalls_result[__NR_rt_tgsigqueueinfo] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_get_priority_max
	syscalls_result[__NR_sched_get_priority_max] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_get_priority_min
	syscalls_result[__NR_sched_get_priority_min] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_getparam
	syscalls_result[__NR_sched_getparam] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_getscheduler
	syscalls_result[__NR_sched_getscheduler] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_rr_get_interval
	syscalls_result[__NR_sched_rr_get_interval] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_setparam
	syscalls_result[__NR_sched_setparam] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_setscheduler
	syscalls_result[__NR_sched_setscheduler] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sched_yield
	syscalls_result[__NR_sched_yield] = CAPMODE_ALLOW;
#endif
#ifdef __NR_select
	syscalls_result[__NR_select] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sendfile
	syscalls_result[__NR_sendfile] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sendmmsg
	syscalls_result[__NR_sendmmsg] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sendmsg
	syscalls_result[__NR_sendmsg] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sendto
	syscalls_result[__NR_sendto] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setfsgid
	syscalls_result[__NR_setfsgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setfsuid
	syscalls_result[__NR_setfsuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setgid
	syscalls_result[__NR_setgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setitimer
	syscalls_result[__NR_setitimer] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setpriority
	syscalls_result[__NR_setpriority] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setregid
	syscalls_result[__NR_setregid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setresgid
	syscalls_result[__NR_setresgid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setresuid
	syscalls_result[__NR_setresuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setreuid
	syscalls_result[__NR_setreuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setrlimit
	syscalls_result[__NR_setrlimit] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setsid
	syscalls_result[__NR_setsid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setsockopt
	syscalls_result[__NR_setsockopt] = CAPMODE_ALLOW;
#endif
#ifdef __NR_setuid
	syscalls_result[__NR_setuid] = CAPMODE_ALLOW;
#endif
#ifdef __NR_shutdown
	syscalls_result[__NR_shutdown] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sigaltstack
	syscalls_result[__NR_sigaltstack] = CAPMODE_ALLOW;
#endif
#ifdef __NR_socket
	syscalls_result[__NR_socket] = CAPMODE_ALLOW;
#endif
#ifdef __NR_socketpair
	syscalls_result[__NR_socketpair] = CAPMODE_ALLOW;
#endif
#ifdef __NR_symlinkat
	syscalls_result[__NR_symlinkat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sync
	syscalls_result[__NR_sync] = CAPMODE_ALLOW;
#endif
#ifdef __NR_syncfs
	syscalls_result[__NR_syncfs] = CAPMODE_ALLOW;
#endif
#ifdef __NR_sync_file_range
	syscalls_result[__NR_sync_file_range] = CAPMODE_ALLOW;
#endif
#ifdef __NR_umask
	syscalls_result[__NR_umask] = CAPMODE_ALLOW;
#endif
#ifdef __NR_uname
	syscalls_result[__NR_uname] = CAPMODE_ALLOW;
#endif
#ifdef __NR_unlinkat
	syscalls_result[__NR_unlinkat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_unshare
	syscalls_result[__NR_unshare] = CAPMODE_ALLOW;
#endif
#ifdef __NR_utimensat
	syscalls_result[__NR_utimensat] = CAPMODE_ALLOW;
#endif
#ifdef __NR_vfork
	syscalls_result[__NR_vfork] = CAPMODE_ALLOW;
#endif
#ifdef __NR_vmsplice
	syscalls_result[__NR_vmsplice] = CAPMODE_ALLOW;
#endif
#ifdef __NR_write
	syscalls_result[__NR_write] = CAPMODE_ALLOW;
#endif
#ifdef __NR_writev
	syscalls_result[__NR_writev] = CAPMODE_ALLOW;
#endif
	return 0;
}
arch_initcall(init_syscalls_result);

/*
 * Process an incoming syscall for Capsicum capability mode.
 * Returns a seccomp BPF response code.
 */
u32 capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	enum capmode_result rc;

	if (!syscalls_result || callnr >= NR_syscalls || callnr < 0)
		return SECCOMP_RET_ERRNO|ECAPMODE;

	rc = syscalls_result[callnr];
	if (rc == CAPMODE_ALLOW)
		return SECCOMP_RET_ALLOW;
	if (rc == CAPMODE_DENY)
		return SECCOMP_RET_ERRNO|ECAPMODE;

	/* Special cases that depend on syscall arguments */
	switch (callnr) {
#ifdef __NR_arch_prctl
	case (__NR_arch_prctl):
		return check_arch_prctl(args);
#endif
#ifdef __NR_kill
	case (__NR_kill):
		return check_kill(args);
#endif
#ifdef __NR_mmap
	case (__NR_mmap):
		return check_mmap(args);
#endif
#ifdef __NR_openat
	case (__NR_openat):
		return check_openat(args);
#endif
#ifdef __NR_prctl
	case (__NR_prctl):
		return check_prctl(args);
#endif
#ifdef __NR_tgkill
	case (__NR_tgkill):
		return check_tgkill(args);
#endif
	default:
		return SECCOMP_RET_ERRNO|ECAPMODE;
	}
}
EXPORT_SYMBOL(capsicum_intercept_syscall);

#else

/* If Capsicum is not enabled, return OK */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	return SECCOMP_RET_ALLOW;
}
#endif
