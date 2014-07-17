/*
 * Copyright (c) 2014 Google, Inc.
 *
 * Licensed under the terms of the GNU GPL License version 2
 *
 * Selftests for seccomp features of prctl(2).
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/unistd.h>

char *filename = "testfile";

/* Way to enter seccomp-bpf mode */
enum BPFEntryMode {
	MODE_FILTER,
	MODE_EXT_ACT,
	MODE_EXT_ACT_TSYNC,
};

pid_t gettid_(void) { return syscall(__NR_gettid); }

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
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define BPF_RETURN_ERRNO(err)	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (err & 0xFFFF))
#define BPF_KILL_PROCESS	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define BPF_ALLOW	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define EXAMINE_SYSCALL	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr))
#define ALLOW_SYSCALL(name)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	BPF_ALLOW
#define KILL_SYSCALL(name)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	BPF_KILL_PROCESS
#define FAIL_SYSCALL(name, err)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	BPF_RETURN_ERRNO(err)

#ifdef SECCOMP_DATA_TID_PRESENT
/* Build environment includes .tgid and .tid fields in seccomp_data */
#define EXAMINE_TGID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tgid))
#define EXAMINE_TID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tid))
#endif

/* Some generally useful filters */
struct sock_filter allow_filter[] = { VALIDATE_ARCHITECTURE,
				      EXAMINE_SYSCALL,
				      BPF_ALLOW };
struct sock_fprog allow_bpf = {.len = (sizeof(allow_filter) /
				       sizeof(allow_filter[0])),
			       .filter = allow_filter};

int prctl_seccomp_bpf(enum BPFEntryMode mode, const struct sock_fprog *fprog)
{
	switch (mode) {
	case MODE_FILTER:
		return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog, 0, 0);
	case MODE_EXT_ACT:
		return prctl(PR_SECCOMP_EXT, SECCOMP_EXT_ACT,
			     SECCOMP_EXT_ACT_FILTER, 0, fprog);
	case MODE_EXT_ACT_TSYNC:
		return prctl(PR_SECCOMP_EXT, SECCOMP_EXT_ACT,
			     SECCOMP_EXT_ACT_FILTER, SECCOMP_FILTER_TSYNC,
			     fprog);
	}
	return -1;
}

int check_bpf_need_nonewpriv(int mode)
{
	/* Root does not need NO_NEW_PRIVS anyway */
	if (getuid() == 0)
		return 0;
	int rc = prctl_seccomp_bpf(mode, &allow_bpf);
	if (rc != -1 || errno != EACCES) {
		printf("[FAIL] (got rc %d errno %d not -EACCESS)\n", rc, errno);
		return 1;
	}
	return 0;
}

int check_bpf_get_seccomp(int mode)
{
	int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) {
		printf("[FAIL] (could not set NO_NEW_PRIVS rc=%d errno=%d)\n",
			rc, errno);
		return 1;
	}
	rc = prctl_seccomp_bpf(mode, &allow_bpf);
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

void setup_police_syscall(int mode)
{
	struct sock_filter filter[] = { VALIDATE_ARCHITECTURE,
					EXAMINE_SYSCALL,
					ALLOW_SYSCALL(read),
					ALLOW_SYSCALL(close),
					FAIL_SYSCALL(open, EBADF),
					BPF_ALLOW };
	struct sock_fprog bpf = {.len = (sizeof(filter) / sizeof(filter[0])),
				       .filter = filter};
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl_seccomp_bpf(mode, &bpf);
}

int ready = 0;
pthread_mutex_t ready_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cv = PTHREAD_COND_INITIALIZER;

pthread_t spawn_other(void *(*fn)(void *), void *param)
{
	pthread_attr_t attr;
	pthread_t other;
	pthread_attr_init(&attr);
	pthread_create(&other, &attr, fn, param);
	return other;
}

void notify_other(void)
{
	pthread_mutex_lock(&ready_mu);
	ready = 1;
	pthread_cond_signal(&ready_cv);
	pthread_mutex_unlock(&ready_mu);
}

int check_policed(int fd)
{
	int rc;
	char buffer[4];
	rc = read(fd, buffer, sizeof(buffer));
	if (rc != 4) {
		printf("[FAIL] expected rc=4 from read(%d), got %d, errno=%d\n",
		       fd, rc, errno);
		return 1;
	}
	rc = close(fd);
	if (rc != 0) {
		printf("[FAIL] close(%d) failed, rc=%d errno=%d\n",
		       fd, rc, errno);
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

int check_unpoliced(void)
{
	int rc;
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		printf("[FAIL] open() failed, rc=%d errno=%d\n", fd, errno);
		return 1;
	}
	rc = read(fd, buffer, sizeof(buffer));
	if (rc != 4) {
		printf("[FAIL] expected rc=4 from read(), got %d\n", rc);
		return 2;
	}
	rc = close(fd);
	if (rc != 0) {
		printf("[FAIL] close() failed, rc=%d errno=%d\n", rc, errno);
		return 3;
	}
	return 0;
}

void *affected_thread(void *arg)
{
	intptr_t fd = (intptr_t)arg;
	intptr_t rc;
	/* Wait for the parent thread to be ready */
	pthread_mutex_lock(&ready_mu);
	while (!ready)
		pthread_cond_wait(&ready_cv, &ready_mu);
	pthread_mutex_unlock(&ready_mu);

	/* Check that syscalls are policed in this thread */
	rc = check_policed(fd);
	return (void *)rc;
}

void *unaffected_thread(void *arg)
{
	intptr_t rc;
	/* Wait for the parent thread to be ready */
	pthread_mutex_lock(&ready_mu);
	while (!ready)
		pthread_cond_wait(&ready_cv, &ready_mu);
	pthread_mutex_unlock(&ready_mu);

	/* Check that syscalls are not policed in this thread */
	rc = check_unpoliced();
	return (void *)rc;
}

int check_bpf_polices_syscalls(int mode)
{
	int rc;
	int fd = open(filename, O_RDONLY);
	void *other_rc;
	/* Another pre-existing thread is unaffected */
	pthread_t other = spawn_other(unaffected_thread, NULL);
	setup_police_syscall(mode);

	/* Check that syscalls are policed in this thread */
	rc = check_policed(fd);
	if (rc != 0) {
		printf("[FAIL] this thread not affected by seccomp-bpf\n");
		return rc;
	}

	/* Check the results of the unaffected other thread */
	notify_other();  /* Allow the other thread to run */
	pthread_join(other, &other_rc);
	if (other_rc != NULL) {
		printf("[FAIL] other thread affected by seccomp-bpf\n");
		return 1;
	}

	return 0;
}

int check_bpf_polices_syscalls_sync(int mode)
{
	int rc;
	intptr_t fd = open(filename, O_RDONLY);
	intptr_t fd2 = dup(fd);
	void *other_rc;
	/* Another pre-existing thread is also affected */
	pthread_t other = spawn_other(affected_thread, (void *)fd);
	setup_police_syscall(mode);
	notify_other();  /* Allow the other thread to run */

	/* Check that syscalls are policed in this thread */
	rc = check_policed(fd2);
	if (rc != 0) {
		printf("[FAIL] this thread not affected by seccomp-bpf\n");
		return rc;
	}

	/* Check that syscalls are policed in the other thread */
	pthread_join(other, &other_rc);
	if (other_rc != NULL) {
		printf("[FAIL] other thread not affected by seccomp-bpf\n");
		return 1;
	}
	return 0;
}

int check_bpf_later_tsync(int mode)
{
	int rc;
	intptr_t fd = open(filename, O_RDONLY);
	intptr_t fd2 = dup(fd);
	void *other_rc;
	/* Another pre-existing thread is also affected after EXT_ACT_TSYNC */
	pthread_t other = spawn_other(affected_thread, (void *)fd);
	setup_police_syscall(mode);

	/* Check that syscalls are policed in this thread */
	rc = check_policed(fd2);
	if (rc != 0) {
		printf("[FAIL] this thread not affected by seccomp-bpf\n");
		return rc;
	}

	/* Now explicitly synchronize the seccomp filter state */
	prctl(PR_SECCOMP_EXT, SECCOMP_EXT_ACT, SECCOMP_EXT_ACT_TSYNC, 0, 0);

	/* Check that syscalls are now policed in the other thread */
	notify_other();  /* Allow the other thread to run */
	pthread_join(other, &other_rc);
	if (other_rc != NULL) {
		printf("[FAIL] other thread not affected by seccomp-bpf\n");
		return 1;
	}
	return 0;
}

int check_bpf_polices_syscall_kill(int mode)
{
	int rc;
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	struct sock_filter filter[] = { VALIDATE_ARCHITECTURE,
					EXAMINE_SYSCALL,
					KILL_SYSCALL(read),
					ALLOW_SYSCALL(close),
					FAIL_SYSCALL(open, EBADF),
					BPF_ALLOW };
	struct sock_fprog bpf = {.len = (sizeof(filter) / sizeof(filter[0])),
				       .filter = filter};
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl_seccomp_bpf(mode, &bpf);
	rc = read(fd, buffer, sizeof(buffer));  /* Generate SIGSYS */
	printf("[FAIL] expected SIGSYS from read(), got %d\n", rc);
	return 1;
}

int check_bpf_with_strict(int mode)
{
	int rc;
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	struct sock_filter filter[] = { VALIDATE_ARCHITECTURE,
					EXAMINE_SYSCALL,
					FAIL_SYSCALL(read, ENOMEM),
					ALLOW_SYSCALL(close),
					BPF_ALLOW };
	struct sock_fprog bpf = {.len = (sizeof(filter) / sizeof(filter[0])),
				       .filter = filter};
	/* Set up seccomp-bpf first */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl_seccomp_bpf(mode, &bpf);

	rc = read(fd, buffer, sizeof(buffer));
	if (rc >= 0) {
		printf("[FAIL] open() succeeded, expected -ENOMEM\n");
		return 1;
	}
	if (errno != ENOMEM) {
		printf("[FAIL] open() failed with errno=%d not ENOMEM\n",
		       errno);
		return 1;
	}

	/* Now turn on seccomp-strict */
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 2;

	/* read() is allowed by seccomp-strict, but seccomp-bpf gives -ENOMEM */
	rc = read(fd, buffer, sizeof(buffer));
	if (rc >= 0)
		return 3;
	if (errno != ENOMEM)
		return 4;

	/* close() allowed by seccomp-bpf, but seccomp-strict gives SIGKILL */
	close(fd);
	syscall(__NR_exit, 99);
	return 0;  /* prevent compiler warning */
}

int check_bpf_with_tids(int mode)
{
#ifdef SECCOMP_DATA_TID_PRESENT
	int rc;
	int fd2;
	char buffer[4];
	int fd = open(filename, O_RDONLY);
	int actual_tid = gettid_();
	int actual_tgid = getpid();
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		/* If tgid/tid info not present, fail with EINVAL */
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),  /* A <- data len */
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
			offsetof(struct seccomp_data, tgid) + sizeof(pid_t),
			0, 1),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
			offsetof(struct seccomp_data, tid) + sizeof(pid_t),
			1, 0),
		BPF_RETURN_ERRNO(EINVAL),
		EXAMINE_SYSCALL,
		/* Only allow read(2) if seccomp_data.tid == tid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 4),
		EXAMINE_TID,  /* A <- tid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, actual_tid, 0, 1),
		BPF_ALLOW,
		BPF_RETURN_ERRNO(ENOTEMPTY),
		/* If seccomp_data.tid != 1, fail close(2) with EMFILE */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_close, 0, 4),
		EXAMINE_TID,  /* A <- tid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 1),
		BPF_ALLOW,
		BPF_RETURN_ERRNO(EMFILE),
		/* Only allow open(2) if seccomp_data.tgid == tgid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 4),
		EXAMINE_TGID,  /* A <- tgid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, actual_tgid, 0, 1),
		BPF_ALLOW,
		BPF_RETURN_ERRNO(ENFILE),
		/* If seccomp_data.tgid != 1, fail dup(2) with ELOOP */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup, 0, 4),
		EXAMINE_TGID,  /* A <- tid */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 1),
		BPF_ALLOW,
		BPF_RETURN_ERRNO(ELOOP),
		BPF_ALLOW
	};
	struct sock_fprog bpf = {
		.len = (sizeof(filter) / sizeof(filter[0])),
		.filter = filter
	};
	/* Set up seccomp-bpf. */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl_seccomp_bpf(mode, &bpf);

	/* read(2) has matching tid, so OK */
	rc = read(fd, buffer, sizeof(buffer));
	if (rc < 0)
		return 1;

	/* We're not tid 1, so close(2) fails */
	rc = close(fd);
	if (rc >= 0)
		return 2;
	if (errno != EMFILE)
		return 3;

	/* open(2) has matching tgid, so OK */
	fd2 = open(filename, O_RDONLY);
	if (fd2 < 0)
		return 4;
	close(fd2);

	/* We're not tgid 1, so dup(2) fails */
	rc = dup(fd);
	if (rc >= 0)
		return 5;
	if (errno != ELOOP)
		return 6;

#else
	printf("Skipping seccomp_data thread info tests due to missing #define\n");
#endif
	return 0;
}

int check_strict_fail_close(int param)
{
	int fd = open(filename, O_RDONLY);
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = close(fd);  /* Generate SIGKILL */
	return 99;
}

int check_strict_fail_getppid(int param)
{
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = getppid();  /* Generate SIGKILL */
	return 99;
}

int check_strict_fail_prctl(int param)
{
	int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	if (rc < 0)
		return 1;
	rc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);  /* Generate SIGKILL */
	return 99;
}

int check_strict_ok(int param)
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
	return 0;  /* prevent compiler warning */
}

#define RUN_FORKED(F, P, S, R)	run_forked(F, #F, P, #P, S, #S, R)
int run_forked(int (*fn)(int), const char *fn_name,
	       int param, const char *param_name,
	       int expected_sig, const char *sig_name,
	       int expected_rc)
{
	int rc;
	int status;
	printf("Run %s(%s)", fn_name, (param == -1) ? "" : param_name);
	if (expected_sig)
		printf(" induces %s", sig_name);
	printf("... ");
	fflush(stdout);
	pid_t child = fork();
	if (child == 0) {
		/* Child: run the test function */
		int rc = fn(param);
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
			printf("[FAIL] (expected signal %d termination;"
				" not status 0x%04x)\n", expected_sig, status);
			return 1;
		}
	} else {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != expected_rc) {
			printf("[FAIL] (expected rc %d exit;"
				" not status 0x%04x)\n", expected_rc, status);
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

	failed |= RUN_FORKED(check_strict_fail_close, -1, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_fail_getppid, -1, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_fail_prctl, -1, SIGKILL, 0);
	failed |= RUN_FORKED(check_strict_ok, -1, 0, 0);

	failed |= RUN_FORKED(check_bpf_need_nonewpriv, MODE_FILTER, 0, 0);
	failed |= RUN_FORKED(check_bpf_get_seccomp, MODE_FILTER, 0, 0);
	failed |= RUN_FORKED(check_bpf_polices_syscalls, MODE_FILTER, 0, 0);
	failed |= RUN_FORKED(check_bpf_polices_syscall_kill, MODE_FILTER,
			     SIGSYS, 0);
	failed |= RUN_FORKED(check_bpf_with_strict, MODE_FILTER, SIGKILL, 0);
	failed |= RUN_FORKED(check_bpf_with_tids, MODE_FILTER, 0, 0);
	/* Same tests but use SECCOMP_EXT_ACT to enter seccomp-bpf mode */
	failed |= RUN_FORKED(check_bpf_need_nonewpriv, MODE_EXT_ACT, 0, 0);
	failed |= RUN_FORKED(check_bpf_get_seccomp, MODE_EXT_ACT, 0, 0);
	failed |= RUN_FORKED(check_bpf_polices_syscalls, MODE_EXT_ACT, 0, 0);
	failed |= RUN_FORKED(check_bpf_polices_syscall_kill, MODE_EXT_ACT,
			     SIGSYS, 0);
	failed |= RUN_FORKED(check_bpf_with_strict, MODE_EXT_ACT, SIGKILL, 0);
	failed |= RUN_FORKED(check_bpf_with_tids, MODE_EXT_ACT, 0, 0);
	/* Check TSYNC operations affect other threads too */
	failed |= RUN_FORKED(check_bpf_polices_syscalls_sync,
			     MODE_EXT_ACT_TSYNC, 0, 0);
	failed |= RUN_FORKED(check_bpf_later_tsync, MODE_FILTER, 0, 0);
	failed |= RUN_FORKED(check_bpf_later_tsync, MODE_EXT_ACT, 0, 0);

	return failed ? -1 : 0;
}
