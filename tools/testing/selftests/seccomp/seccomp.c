/*
 * Copyright (c) 2014 Google, Inc.
 *
 * Licensed under the terms of the GNU GPL License version 2
 *
 * Selftests for seccomp features of prctl(2).
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/unistd.h>

static char *filename = "testfile";

/* Determine expected syscall architecture */
#if defined(__i386__)
#define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define ARCH_NR	AUDIT_ARCH_X86_64
#else
#warning "Platform does not support seccomp filter yet"
#define ARCH_NR	0
#endif

/* Macros for BPF generation */
#define VALIDATE_ARCHITECTURE	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define BPF_RETURN_ERRNO(err)	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (err & 0xFFFF))
#define BPF_KILL_PROCESS	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define BPF_ALLOW	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define EXAMINE_SYSCALL					\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr))
#define ALLOW_SYSCALL(name)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	BPF_ALLOW
#define FAIL_SYSCALL(name, err)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	BPF_RETURN_ERRNO(err)

/* Some generally useful filters */
struct sock_filter allow_filter[] = { VALIDATE_ARCHITECTURE,
				      EXAMINE_SYSCALL,
				      BPF_ALLOW };
struct sock_fprog allow_bpf = {.len = (sizeof(allow_filter) /
				       sizeof(allow_filter[0])),
			       .filter = allow_filter};

int check_bpf_need_nonewpriv(void)
{
	/* Root does not need NO_NEW_PRIVS anyway */
	if (getuid() == 0)
		return 0;
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &allow_bpf, 0, 0);
	if (rc != -1 || errno != EACCES) {
		printf("[FAIL] (got rc %d errno %d not -EACCESS)\n", rc, errno);
		return 1;
	}
	return 0;
}

int check_bpf_get_seccomp(void)
{
	int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) {
		printf("[FAIL] (could not set NO_NEW_PRIVS rc=%d errno=%d)\n",
			rc, errno);
		return 1;
	}
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &allow_bpf, 0, 0);
	if (rc < 0) {
		printf("[FAIL] (could not SET_SECCOMP rc=%d errno=%d)\n",
			rc, errno);
		return 1;
	}
	rc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
	if (rc != SECCOMP_MODE_FILTER) {
		printf("[FAIL] (expected GET_SECCOMP to return %d not %d\n",
			SECCOMP_MODE_FILTER, rc);
		return 1;
	}
	return 0;
}

int check_bpf_polices_syscalls(void)
{
	int rc;
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	struct sock_filter filter[] = { VALIDATE_ARCHITECTURE,
					EXAMINE_SYSCALL,
					ALLOW_SYSCALL(read),
					ALLOW_SYSCALL(close),
					FAIL_SYSCALL(open, EBADF),
					BPF_ALLOW };
	struct sock_fprog bpf = {.len = (sizeof(filter) / sizeof(filter[0])),
				       .filter = filter};
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf, 0, 0);
	rc = read(fd, buffer, sizeof(buffer));
	if (rc != 4) {
		printf("[FAIL] expected rc=4 from read(), got %d\n", rc);
		return 1;
	}
	rc = close(fd);
	if (rc != 0) {
		printf("[FAIL] close() failed, rc=%d errno=%d\n", rc, errno);
		return 1;
	}
	rc = open(filename, O_RDONLY);
	if (rc >= 0) {
		printf("[FAIL] open() succeeded, expected -EBADF\n");
		return 1;
	}
	if (errno != EBADF) {
		printf("[FAIL] open() failed with errno=%d not EBADF\n", errno);
		return 1;
	}
	return 0;
}

int check_bpf_prevents_strict(void)
{
	int rc;
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &allow_bpf, 0, 0);
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc != -1 || errno != EINVAL)
		return errno;
	return 0;
}

int check_strict_fail_close(void)
{
	int fd = open(filename, O_RDONLY);
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = close(fd);  /* Generate SIGKILL */
	return 99;
}

int check_strict_fail_getppid(void)
{
	int fd = open(filename, O_RDONLY);
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = getppid();  /* Generate SIGKILL */
	return 99;
}

int check_strict_fail_prctl(void)
{
	int fd = open(filename, O_RDONLY);
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);  /* Generate SIGKILL */
	return 99;
}

int check_strict_ok(void)
{
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	/* read(2), write(2), _exit(2) & sigreturn(2) allowed */
	rc = read(fd, buffer, sizeof(buffer));
	if (rc != 4)
		return 2;
	/*
	 * Go directly to the syscall to prevent any unexpected additional
	 * syscalls occurring
	 */
	syscall(__NR_exit, 0);
}

#define RUN_FORKED(F, S, R)	run_forked(F, #F, S, R)
int run_forked(int (*fn)(void), const char *fn_name,
	       int expected_sig, int expected_rc)
{
	int rc;
	int status;
	printf("Run %s()... ", fn_name);
	fflush(stdout);
	pid_t child = fork();
	if (child == 0) {
		/* Child: run the test function */
		int rc = fn();
		exit(rc);
	}
	/* Parent: reap the child */
	rc = waitpid(child, &status, 0);
	if (rc != child) {
		printf("[FAIL] (waitpid(%d,...) returned %d)\n", child, rc);
		return 1;
	}
	if (expected_sig != 0) {
		if (!WIFSIGNALED(status) || WTERMSIG(status) != expected_sig) {
			printf("[FAIL] (expected signal %d termination, "
				"not status 0x%04x)\n", expected_sig, status);
			return 1;
		}
	} else {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != expected_rc) {
			printf("[FAIL] (expected rc %d exit, "
				"not status 0x%04x)\n", expected_rc, status);
			return 1;
		}
	}
	printf("[OK]\n");
	return 0;

}

int main(int argc, char *argv[])
{
	int failed = 0;
	if (argc >= 2)
		filename = argv[1];

	failed |= RUN_FORKED(check_strict_fail_close, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_fail_getppid, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_fail_prctl, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_ok, 0, 0);
	failed |= RUN_FORKED(check_bpf_need_nonewpriv, 0, 0);
	failed |= RUN_FORKED(check_bpf_get_seccomp, 0, 0);
	failed |= RUN_FORKED(check_bpf_polices_syscalls, 0, 0);
	failed |= RUN_FORKED(check_bpf_prevents_strict, 0, 0);

	return failed ? -1 : 0;
}
