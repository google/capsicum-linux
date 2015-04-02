/*
 * Copyright (c) 2015 Google, Inc.
 *
 * Licensed under the terms of the GNU GPL License version 2
 *
 * Selftests for clone4(2) and the flags unique to it.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "clonetest.h"

void *stack_top;
const char *verbose;

#ifndef CLONE_AUTOREAP
#define CLONE_AUTOREAP 0x00001000
#endif
#ifndef CLONE_FD
#define CLONE_FD       0x00400000      /* Signal exit via file descriptor */
#endif
#ifndef CLONEFD_CLOEXEC
#define CLONEFD_CLOEXEC	0x00000001
#endif
#ifndef CLONEFD_NONBLOCK
#define CLONEFD_NONBLOCK	0x00000002
#endif

#ifndef CLONEFD_IOC_GETTID
#define CLONEFD_IOC_GETTID	_IO('C', 1)
#define CLONEFD_IOC_GETPID	_IO('C', 2)
#endif

struct user_desc;
static int clone4_(uint64_t flags,
		   pid_t *ptid, struct user_desc *tls, pid_t *ctid,
		   int *fd, int fd_flags)
{
#ifdef __NR_clone4
	struct clone4_args args = {};

	memset(&args, 0, sizeof(args));
	args.ptid = ptid;
	args.ctid = ctid;
	args.tls = tls;
	args.clonefd = fd;
	args.clonefd_flags = fd_flags;
	errno = 0;
	return syscall(__NR_clone4,
		       (int)(flags >> 32), (int)(flags & 0xFFFFFFFF),
		       (unsigned int)sizeof(args), &args, 0, 0);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int sigchld_count;
static void sig_recorder(int signum)
{
	if (signum == SIGCHLD) {
		vprintf("[%d] received SIGCHLD\n", gettid_());
		sigchld_count++;
	}
}

#define RUN_TEST(testfn, sa_flags) run_test(testfn, #testfn, sa_flags)
static inline int run_test(int (*fn)(void), const char *name, int sa_flags)
{
	int rc;
	struct sigaction action;
	struct sigaction original;

	printf("Run %s()... ", name);
	fflush(stdout);
	sigchld_count = 0;
	action.sa_handler = sig_recorder;
	action.sa_flags = sa_flags;
	sigaction(SIGCHLD, &action, &original);

	rc = fn();

	if (rc < 0)
		printf("[Skipped]\n");
	else if (rc > 0)
		printf("[Fail]\n");
	else
		printf("[OK]\n");
	sigaction(SIGCHLD, &original, NULL);
	return rc > 0 ? rc : 0;
}

static int check_clone4(void)
{
	int fail = 0;
	pid_t child, reaped;
	int status;

	child = clone4_(SIGCHLD, NULL, NULL, NULL, NULL, 0);
	if (child == 0)
		exit(child_just_exit(NULL));
	vprintf("[%d] clone4() returned child=%d errno=%d\n",
		gettid_(), child, errno);
	ASSERT(child > 0);

	usleep(200000);  /* interrupted by signal */
	EXPECT(pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);
	EXPECT(sigchld_count == 1);
	return fail;
}

static int check_clone_autoreap(void)
{
	int fail = 0;
	pid_t child, reaped;
	int status;

	child = clone4_(SIGCHLD|CLONE_AUTOREAP, NULL, NULL, NULL, NULL, 0);
	if (child == 0)
		exit(child_just_exit(NULL));
	vprintf("[%d] clone4() returned child=%d errno=%d\n",
		gettid_(), child, errno);
	ASSERT(child > 0);

	usleep(200000);  /* interrupted by signal */

	/* Child automatically reaped */
	EXPECT(!pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == -1);
	EXPECT(errno == ECHILD);
	/* SIGCHLD was still generated, though */
	EXPECT(sigchld_count == 1);
	return fail;
}

static int check_clone_autoreap_signals(void)
{
	int fail = 0;
	pid_t child, waited;
	int status;

	child = clone4_(SIGCHLD|CLONE_AUTOREAP, NULL, NULL, NULL, NULL, 0);
	if (child == 0)
		exit(child_loop_forever(NULL));
	vprintf("[%d] clone4() returned child=%d errno=%d\n",
		gettid_(), child, errno);
	ASSERT(child > 0);

	usleep(200000);
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, WNOHANG|WUNTRACED|WCONTINUED);
	EXPECT(waited == 0);

	/* SIGSTOPped child should be visible to waitpid(WUNTRACED) */
	errno = 0;
	status = kill(child, SIGSTOP);
	EXPECT(status == 0);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	/* SIGCONTed child should be visible to waitpid(WCONTINUED) */
	status = kill(child, SIGCONT);
	EXPECT(status == 0);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);

	EXPECT(pid_present(child));
	vprintf("[%d] kill(%d, SIGKILL)\n", gettid_(), child);
	status = kill(child, SIGKILL);
	EXPECT(status == 0);
	usleep(100000);  /* interrupted by signal */

	/* Child automatically reaped */
	usleep(100000);
	EXPECT(!pid_present(child));
	waited = waitpid(child, &status, 0);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);

	/* SIGCHLD signals were still generated, though */
	EXPECT(sigchld_count > 1);
	return fail;
}

static int check_clone_autoreap_nosignals(void)
{
	int fail = 0;
	pid_t child, waited;
	int status;

	child = clone4_(CLONE_AUTOREAP, NULL, NULL, NULL, NULL, 0);
	if (child == 0)
		exit(child_loop_forever(NULL));
	vprintf("[%d] clone4() returned child=%d errno=%d\n",
		gettid_(), child, errno);
	ASSERT(child > 0);

	usleep(200000);
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, WNOHANG|WUNTRACED|WCONTINUED);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	/* SIGSTOPped child invisible to waitpid(WUNTRACED) */
	errno = 0;
	status = kill(child, SIGSTOP);
	EXPECT(status == 0);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	/* ...unless __WCLONE also specified */
	waited = waitpid(child, &status, __WCLONE|WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	/* SIGCONTed child invisible to waitpid(WCONTINUED) */
	status = kill(child, SIGCONT);
	EXPECT(status == 0);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	/* ...unless __WCLONE also specified */
	waited = waitpid(child, &status, __WCLONE|WUNTRACED|WCONTINUED);
	EXPECT(waited == child);

	EXPECT(pid_present(child));
	usleep(20000);
	sigchld_count = 0;
	vprintf("[%d] kill(%d, SIGKILL)\n", gettid_(), child);
	status = kill(child, SIGKILL);
	EXPECT(status == 0);
	usleep(100000);  /* interrupted by signal */

	/* Child automatically reaped */
	usleep(100000);
	EXPECT(!pid_present(child));
	waited = waitpid(child, &status, __WCLONE);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	EXPECT(sigchld_count == 0);
	return fail;
}

static int do_ptrace(pid_t child)
{
	int fail = 0;
	int status;
	pid_t waited;

	EXPECT(sigchld_count == 0);
	status = ptrace(PTRACE_ATTACH, child, NULL, NULL);
	vprintf("    [%d] ptrace(ATTACH, %d) => rc=%d errno %d\n",
		gettid_(), child, status, errno);
	ASSERT(status == 0);
	usleep(10000);
	EXPECT(sigchld_count == 1);

	waited = waitpid(child, &status, __WALL|WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	vprintf("    [%d] kill(%d, SIGKILL)\n", gettid_(), child);
	status = kill(child, SIGKILL);
	EXPECT(status == 0);
	usleep(200000);
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, __WALL);
	EXPECT(waited == child);
	usleep(200000);
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);

	/* Child auto-reaps now ptracer has waited. */
	EXPECT(!pid_present(child));

	vprintf("    [%d] exiting\n", gettid_());
	return fail;
}

static int check_clone_autoreap_ptrace(int signal)
{
	int fail = 0;
	pid_t child, waited, tracer;
	int status;

	if (!nonparent_ptrace_allowed())
		return -1;
	child = clone4_(signal|CLONE_AUTOREAP, NULL, NULL, NULL, NULL, 0);
	if (child == 0)
		exit(child_loop_forever(NULL));
	vprintf("[%d] clone4() returned child=%d errno=%d\n",
		gettid_(), child, errno);
	ASSERT(child > 0);
	usleep(200000);
	EXPECT(pid_present(child));

	/* Perform ptrace operations in a different child */
	tracer = fork();
	if (tracer == 0)
		exit(do_ptrace(child));

	vprintf("[%d] waitpid(tracer=%d)\n", gettid_(), tracer);
	do {
		waited = waitpid(tracer, &status, 0);
	} while (waited == -1 && errno == EINTR);
	EXPECT(waited == tracer);
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);
	EXPECT(!pid_present(child));

	return fail;
}

static int check_clone_autoreap_signals_ptrace(void)
{
	return check_clone_autoreap_ptrace(SIGCHLD);
}

static int check_clone_autoreap_nosignals_ptrace(void)
{
	return check_clone_autoreap_ptrace(0);
}

static int check_clone_fd(void)
{
	int fail = 0;
	pid_t child, reaped;
	int fd = -1;
	int rc, status;
	struct clonefd_info fdinfo;
	struct pollfd fdp;
	unsigned char buffer[128];

	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd, 0);
	if (child == 0)
		exit(child_wait_then_exit(NULL));
	vprintf("[%d] clone4() returned child=%d fd=%d errno=%d\n",
		gettid_(), child, fd, errno);
	ASSERT(child > 0);

	/* Unreaped child has pid/tid accessible via ioctl */
	rc = ioctl(fd, CLONEFD_IOC_GETTID, 0);
	EXPECT(rc == child);
	rc = ioctl(fd, CLONEFD_IOC_GETPID, 0);
	EXPECT(rc == child);

	/* Wait on the file descriptor for child exit. */
	fdp.fd = fd;
	fdp.events = POLLIN | POLLERR | POLLHUP;
	fdp.revents = 0;
	do {
		rc = poll(&fdp, 1, 5000);
	} while (rc == -1 && errno == EINTR);
	EXPECT(rc == 1);
	EXPECT(fdp.revents & POLLHUP);
	EXPECT(fdp.revents & POLLIN);
	EXPECT(sigchld_count == 1);

	/* Read retrieves status info */
	rc = read(fd, &fdinfo, sizeof(fdinfo));
	EXPECT(rc == sizeof(fdinfo));
	vprintf("[%d] read(%d): {code=%u, status=%u, utime=%lu, stime=%lu}\n",
		gettid_(), fd, fdinfo.code, fdinfo.status,
		(long)fdinfo.utime, (long)fdinfo.stime);
	EXPECT(fdinfo.code == CLD_EXITED);
	EXPECT(WIFEXITED(fdinfo.status));
	EXPECT(WEXITSTATUS(fdinfo.status) == 0);

	/* Second read fails */
	rc = read(fd, buffer, sizeof(buffer));
	EXPECT(rc == 0);

	/* Unreaped zombie child has pid accessible via ioctl */
	rc = ioctl(fd, CLONEFD_IOC_GETTID, 0);
	EXPECT(rc == child);

	/* Still need to reap the child */
	EXPECT(pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);

	/* Reaped child has zero pid value returned */
	rc = ioctl(fd, CLONEFD_IOC_GETTID, 0);
	EXPECT(rc == 0);

	close(fd);
	return fail;
}

static int check_clone_fd_reap_then_read(void)
{
	int fail = 0;
	pid_t child, reaped;
	int fd = -1;
	int rc, status;
	struct clonefd_info fdinfo;

	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd, 0);
	if (child == 0)
		exit(child_just_exit(NULL));
	vprintf("[%d] clone4() returned child=%d fd=%d errno=%d\n",
		gettid_(), child, fd, errno);
	ASSERT(child > 0);

	/* Reap the child while fd still open*/
	EXPECT(pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);

	/* Read retrieves status info */
	rc = read(fd, &fdinfo, sizeof(fdinfo));
	EXPECT(rc == sizeof(fdinfo));
	vprintf("[%d] read(%d): {code=%u, status=%u, utime=%lu, stime=%lu}\n",
		gettid_(), fd, fdinfo.code, fdinfo.status,
		(long)fdinfo.utime, (long)fdinfo.stime);
	EXPECT(fdinfo.code == CLD_EXITED);
	EXPECT(WIFEXITED(fdinfo.status));
	EXPECT(WEXITSTATUS(fdinfo.status) == 0);

	close(fd);
	return fail;
}

static int check_clone_fd_cloexec(void)
{
	int fail = 0;
	pid_t child, reaped;
	int fd = -1;
	int rc, status;

	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd,
			CLONEFD_CLOEXEC);
	if (child == 0)
		exit(child_just_exit(NULL));
	vprintf("[%d] clone4() returned child=%d fd=%d errno=%d\n",
		gettid_(), child, fd, errno);
	ASSERT(child > 0);

	/* Check CLOEXEC status */
	rc = fcntl(fd, F_GETFD, 0);
	EXPECT(rc & FD_CLOEXEC);

	/* Still need to reap the child */
	EXPECT(pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);
	close(fd);

	return fail;
}

static int check_clone_fd_nonblock(void)
{
	int fail = 0;
	pid_t child, reaped;
	int fd = -1;
	int rc, status;
	struct clonefd_info fdinfo;
	struct pollfd fdp;

	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd,
			CLONEFD_NONBLOCK);
	if (child == 0)
		exit(child_wait_then_exit(NULL));
	vprintf("[%d] clone4() returned child=%d fd=%d errno=%d\n",
		gettid_(), child, fd, errno);
	ASSERT(child > 0);

	/* Check NONBLOCK status */
	rc = fcntl(fd, F_GETFL, 0);
	EXPECT(rc & O_NONBLOCK);

	/* Read doesn't block */
	errno = 0;
	rc = read(fd, &fdinfo, sizeof(fdinfo));
	EXPECT(rc == -1);
	EXPECT(errno == EWOULDBLOCK || errno == EAGAIN);

	/* Wait on the file descriptor for child exit. */
	fdp.fd = fd;
	fdp.events = POLLIN | POLLERR | POLLHUP;
	fdp.revents = 0;
	do {
		rc = poll(&fdp, 1, 5000);
	} while (rc == -1 && errno == EINTR);
	EXPECT(rc == 1);
	EXPECT(fdp.revents & POLLHUP);
	EXPECT(fdp.revents & POLLIN);
	EXPECT(sigchld_count == 1);

	/* Read now retrieves status info */
	rc = read(fd, &fdinfo, sizeof(fdinfo));
	EXPECT(rc == sizeof(fdinfo));
	vprintf("[%d] read(%d): {code=%u, status=%u, utime=%lu, stime=%lu}\n",
		gettid_(), fd, fdinfo.code, fdinfo.status,
		(long)fdinfo.utime, (long)fdinfo.stime);
	EXPECT(fdinfo.code == CLD_EXITED);
	EXPECT(WIFEXITED(fdinfo.status));
	EXPECT(WEXITSTATUS(fdinfo.status) == 0);

	/* Still need to reap the child */
	EXPECT(pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFEXITED(status));
	EXPECT(WEXITSTATUS(status) == 0);
	close(fd);

	return fail;
}

static int check_clone_fd_invalid(void)
{
	int fail = 0;
	pid_t child;
	int fd = -1;

	/* Unexpected clone flag */
	child = clone4_(SIGCHLD|CLONE_FD|0x100000000, NULL, NULL, NULL, &fd, 0);
	if (child == 0)
		exit(1);
	EXPECT(child == -1);
	EXPECT(errno == EINVAL);
	EXPECT(fd == -1);

	/* Unexpected clone_fd flag */
	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd, O_DIRECT);
	if (child == 0)
		exit(1);
	EXPECT(child == -1);
	EXPECT(errno = EINVAL);
	EXPECT(fd == -1);

	return fail;
}

static int check_clone_fd_write(void)
{
	int fail = 0;
	pid_t child, waited;
	int fd = -1;
	int rc, status;
	struct clonefd_info fdinfo;
	struct pollfd fdp;
	unsigned char signum;

	child = clone4_(SIGCHLD|CLONE_FD, NULL, NULL, NULL, &fd, 0);
	if (child == 0)
		exit(child_loop_forever(NULL));
	vprintf("[%d] clone4() returned child=%d fd=%d errno=%d\n",
		gettid_(), child, fd, errno);
	ASSERT(child > 0);

	/* Send a SIGSTOP */
	signum = SIGSTOP;
	rc = write(fd, &signum, 1);
	vprintf("[%d] write(%d, &SIGSTOP) = %d errno %d\n",
		gettid_(), fd, rc, errno);
	EXPECT(rc == 1);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	/* Send a SIGCONT */
	signum = SIGCONT;
	rc = write(fd, &signum, 1);
	vprintf("[%d] write(%d, &SIGCONT) = %d errno %d\n",
		gettid_(), fd, rc, errno);
	EXPECT(rc == 1);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(!WIFSTOPPED(status));

	EXPECT(pid_present(child));
	signum = SIGKILL;
	rc = write(fd, &signum, 1);
	vprintf("[%d] write(%d, &SIGKILL) = %d errno %d\n",
		gettid_(), fd, rc, errno);
	EXPECT(rc == 1);

	/* Wait on the file descriptor for child exit. */
	fdp.fd = fd;
	fdp.events = POLLIN | POLLERR | POLLHUP;
	fdp.revents = 0;
	do {
		rc = poll(&fdp, 1, 5000);
	} while (rc == -1 && errno == EINTR);
	EXPECT(rc == 1);
	EXPECT(fdp.revents & POLLHUP);
	EXPECT(fdp.revents & POLLIN);
	EXPECT(sigchld_count >= 1);

	/* Read retrieves status info. */
	rc = read(fd, &fdinfo, sizeof(fdinfo));
	EXPECT(rc == sizeof(fdinfo));
	vprintf("[%d] read(%d): {code=%u, status=%u, utime=%lu, stime=%lu}\n",
		gettid_(), fd, fdinfo.code, fdinfo.status,
		(long)fdinfo.utime, (long)fdinfo.stime);
	EXPECT(fdinfo.code == CLD_KILLED);
	EXPECT(WIFSIGNALED(fdinfo.status));
	EXPECT(WTERMSIG(fdinfo.status) == SIGKILL);

	/* Still need to reap the child */
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, 0);
	EXPECT(waited == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);

	close(fd);
	return fail;
}

int main(int argc, char **argv)
{
	int fail = 0;
	void *stack = malloc(STACK_SIZE);

	if (!stack) {
		fprintf(stderr, "Failed to allocate stack of size %d\n",
			STACK_SIZE);
		exit(1);
	}
	stack_top = stack + STACK_SIZE;
	verbose = getenv("VERBOSE");

	fail += RUN_TEST(check_clone4, 0);
	fail += RUN_TEST(check_clone_autoreap, 0);
	fail += RUN_TEST(check_clone_autoreap_signals, 0);
	fail += RUN_TEST(check_clone_autoreap_nosignals, 0);
	fail += RUN_TEST(check_clone_autoreap_signals_ptrace, 0);
	fail += RUN_TEST(check_clone_autoreap_nosignals_ptrace, 0);
	fail += RUN_TEST(check_clone_fd, 0);
	fail += RUN_TEST(check_clone_fd_reap_then_read, 0);
	fail += RUN_TEST(check_clone_fd_cloexec, 0);
	fail += RUN_TEST(check_clone_fd_nonblock, 0);
	fail += RUN_TEST(check_clone_fd_invalid, 0);
	fail += RUN_TEST(check_clone_fd_write, 0);

	return fail;
}
