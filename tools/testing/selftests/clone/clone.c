/*
 * Copyright (c) 2015 Google, Inc.
 *
 * Licensed under the terms of the GNU GPL License version 2
 *
 * Selftests for clone(2).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "clonetest.h"

void *stack_top;
const char *verbose;

struct user_desc;
typedef int (*clone_wrapper)(int (*fn)(void *), void *child_stack,
			uint64_t flags, void *arg,
			pid_t *ptid, struct user_desc *tls, pid_t *ctid);

static int clone_(int (*fn)(void *), void *child_stack,
		  uint64_t flags, void *arg,
		  pid_t *ptid, struct user_desc *tls, pid_t *ctid)
{
	if ((flags >> 32) != 0) {
		fprintf(stderr, "Unexpected extra flags %016llx\n",
		       (unsigned long long)flags);
		exit(1);
	}
	/* The glibc wrapper handles arch-specific oddities. */
	return clone(fn, child_stack, (flags & 0xFFFFFFFF), arg,
		     ptid, tls, ctid);
}

static int clone4_(int (*fn)(void *), void *child_stack,
		   uint64_t flags, void *arg,
		   pid_t *ptid, struct user_desc *tls, pid_t *ctid)
{
#ifdef __NR_clone4
	struct clone4_args args = {};
	int rc;

	memset(&args, 0, sizeof(args));
	args.ptid = ptid;
	args.ctid = ctid;
	args.tls = tls;
	rc = syscall(__NR_clone4, (int)(flags >> 32), (int)(flags & 0xFFFFFFFF),
		     (unsigned int)sizeof(args), &args, 0, 0);
	if (rc == 0) {  /* Child */
		rc = fn(arg);
		exit(rc);
	}
	return rc;
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

#define RUN_TEST(testfn, clonefn, sa_flags) \
	run_test(testfn, #testfn, clonefn, #clonefn, sa_flags, #sa_flags)
static inline int run_test(int (*fn)(clone_wrapper, int), const char *name,
			   clone_wrapper clonefn, const char *clonefn_name,
			   int sa_flags, const char *sa_flagstr)
{
	int rc;
	struct sigaction action;
	struct sigaction original;

	printf("Run %s(%s) using %s... ", name, sa_flagstr, clonefn_name);
	fflush(stdout);
	sigchld_count = 0;
	action.sa_handler = sig_recorder;
	action.sa_flags = sa_flags;
	sigaction(SIGCHLD, &action, &original);

	rc = fn(clonefn, sa_flags);

	if (rc < 0)
		printf("[Skipped]\n");
	else if (rc > 0)
		printf("[Fail]\n");
	else
		printf("[OK]\n");
	sigaction(SIGCHLD, &original, NULL);
	return rc > 0 ? rc : 0;
}

/* Test cases */
static int check_clone(clone_wrapper clonefn, int sa_flags)
{
	int fail = 0;
	pid_t child, reaped;
	int status;

	child = clonefn(child_just_exit, stack_top,
			SIGCHLD,
			NULL, NULL, NULL, NULL);
	vprintf("[%d] clone() returned child=%d errno=%d\n",
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

static int check_no_signals(clone_wrapper clonefn, int sa_flags)
{
	int fail = 0;
	pid_t child, waited;
	int status;

	/* No exit signal specified */
	child = clonefn(child_loop_forever, stack_top,
			0,
			NULL, NULL, NULL, NULL);
	vprintf("[%d] clone() returned child=%d\n", gettid_(), child);
	ASSERT(child > 0);

	usleep(200000);
	EXPECT(pid_present(child));

	/* SIGSTOPped child not visible to waitpid(WUNTRACED) */
	errno = 0;
	status = kill(child, SIGSTOP);
	EXPECT(status == 0);
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	/* ...unless __WCLONE also specified */
	waited = waitpid(child, &status, __WCLONE|WUNTRACED|WCONTINUED);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	/* SIGCONTed child not be visible to waitpid(WCONTINUED) */
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
	usleep(200000);

	/* Invisible to normal waitpid() call */
	waited = waitpid(child, &status, WNOHANG);
	EXPECT(waited == -1);
	EXPECT(errno == ECHILD);

	/* ...unless __WCLONE specified */
	waited = waitpid(child, &status, __WCLONE);
	EXPECT(waited == child);
	EXPECT(!pid_present(child));
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);
	EXPECT(sigchld_count == 0);
	return fail;
}

static int check_sa_nocldwait(clone_wrapper clonefn, int sa_flags)
{
	int fail = 0;
	pid_t child, reaped;
	int status;

	ASSERT(sa_flags & SA_NOCLDWAIT);
	child = clonefn(child_just_exit, stack_top,
			SIGCHLD,
			NULL, NULL, NULL, NULL);
	vprintf("[%d] clone() returned child=%d\n", gettid_(), child);
	ASSERT(child > 0);

	usleep(10000);  /* yield */

	/* Child automatically reaped */
	EXPECT(!pid_present(child));
	reaped = waitpid(child, &status, 0);
	EXPECT(reaped == -1);
	EXPECT(errno == ECHILD);

	/* SIGCHLD was still generated, though */
	EXPECT(sigchld_count == 1);
	return fail;
}

static int check_sigstop(clone_wrapper clonefn, int sa_flags)
{
	int fail = 0;
	pid_t child, waited;
	int status;

	child = clonefn(child_loop_forever, stack_top,
			SIGCHLD,
			NULL, NULL, NULL, NULL);
	vprintf("[%d] clone() returned child=%d\n", gettid_(), child);
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
	usleep(200000);
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);

	EXPECT(!pid_present(child));  /* now reaped */
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);
	if (sa_flags & SA_NOCLDSTOP)
		EXPECT(sigchld_count == 1);
	else
		EXPECT(sigchld_count > 1);
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

	waited = waitpid(child, &status, WUNTRACED|WCONTINUED);
	EXPECT(waited == child);
	EXPECT(WIFSTOPPED(status));
	EXPECT(WSTOPSIG(status) == SIGSTOP);

	vprintf("    [%d] kill(%d, SIGKILL)\n", gettid_(), child);
	status = kill(child, SIGKILL);
	EXPECT(status == 0);
	usleep(200000);
	EXPECT(pid_present(child));
	waited = waitpid(child, &status, 0);
	EXPECT(waited == child);
	usleep(200000);
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);

	/*
	 * Reporting child death to tracer does not reap the zombie; it is left
	 * for the original parent to reap.
	 */
	EXPECT(pid_present(child));

	vprintf("    [%d] exiting\n", gettid_());
	return fail;
}

static int check_ptrace(clone_wrapper clonefn, int sa_flags)
{
	int fail = 0;
	pid_t child, tracer, waited;
	int status;

	if (!nonparent_ptrace_allowed())
		return -1;
	child = clonefn(child_loop_forever, stack_top,
			SIGCHLD,
			NULL, NULL, NULL, NULL);
	vprintf("[%d] clone() returned child=%d\n", gettid_(), child);
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

	EXPECT(pid_present(child));
	kill(child, SIGKILL);
	waited = waitpid(child, &status, 0);
	EXPECT(waited == child);
	EXPECT(WIFSIGNALED(status));
	EXPECT(WTERMSIG(status) == SIGKILL);
	EXPECT(!pid_present(child));

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

	fail += RUN_TEST(check_clone, clone_, 0);
	fail += RUN_TEST(check_no_signals, clone_, 0);
	fail += RUN_TEST(check_sa_nocldwait, clone_, SA_NOCLDWAIT);
	fail += RUN_TEST(check_sigstop, clone_, 0);
	fail += RUN_TEST(check_sigstop, clone_, SA_NOCLDSTOP);
	fail += RUN_TEST(check_ptrace, clone_, 0);

	fail += RUN_TEST(check_clone, clone4_, 0);
	fail += RUN_TEST(check_no_signals, clone4_, 0);
	fail += RUN_TEST(check_sa_nocldwait, clone4_, SA_NOCLDWAIT);
	fail += RUN_TEST(check_sigstop, clone4_, 0);
	fail += RUN_TEST(check_sigstop, clone4_, SA_NOCLDSTOP);
	fail += RUN_TEST(check_ptrace, clone4_, 0);

	return fail;
}
