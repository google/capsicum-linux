/*
 * Tests for the process descriptor API for Linux.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <misc/test_harness.h>

#include "procdesc.h"

TEST(use_pdfork) {
	int r, pd = -1;

	r = pdfork(&pd, 0);
	ASSERT_GE(r, 0);

	if (r == 0) {
		/* We're the child. */
		ASSERT_EQ(pd, -1);
		exit(0);
	}

	ASSERT_NE(pd, -1);
	close(pd);
}

FIXTURE(pdexit) {
	int pd;
	int pipe;
	int pid;
};

FIXTURE_SETUP(pdexit) {
	int r;
	int pipes[2];

	r = pipe(pipes);
	ASSERT_GE(r, 0);
	self->pipe = pipes[1];

	r = pdfork(&self->pd, 0);
	ASSERT_GE(r, 0);

	if (r == 0) {
		/* We're the child. */
		read(pipes[0], &r, sizeof(r));
		exit(r);
	} else {
		self->pid = r;
	}
}

FIXTURE_TEARDOWN(pdexit) {}

/* Can we poll a process descriptor? */
TEST_F(pdexit, poll) {
	struct timeval timeout = {0, 0};
	fd_set fds;
	int r;
	int pd = self->pd;

	FD_SET(pd, &fds);
	r = select(pd+1, NULL, NULL, &fds, &timeout);
	EXPECT_EQ(r, 0);

	/* Tell the child to exit. (The value of r doesn't matter here.) */
	write(self->pipe, &r, sizeof(r));

	FD_SET(pd, &fds);
	r = select(pd+1, NULL, NULL, &fds, NULL);
	EXPECT_EQ(r, 1);

	close(pd);
}

/* Can multiple processes poll on the same descriptor? */
TEST_F(pdexit, poll_multiple) {
	fd_set fds;
	int r, other_pid;
	int pd = self->pd;
	struct timeval timeout = {0, 0};

	r = fork();
	ASSERT_GE(r, 0);
	if (!r) {
		/* Give the other processes time to get set up, then
		   terminate the child. */
		sleep(1);
		write(self->pipe, &r, sizeof(r));
		exit(0);
	}

	other_pid = fork();
	ASSERT_GE(other_pid, 0);

	FD_SET(pd, &fds);
	r = select(pd+1, NULL, NULL, &fds, &timeout);
	EXPECT_EQ(r, 0);

	FD_SET(pd, &fds);
	r = select(pd+1, NULL, NULL, &fds, NULL);
	EXPECT_EQ(r, 1);

	close(pd);

	if (other_pid) {
		waitpid(other_pid, &r, 0);
		EXPECT_TRUE(WIFEXITED(r));
		EXPECT_EQ(WEXITSTATUS(r), 0);
	} else {
		exit(0);
	}
}

/*
 * Does a pdfork()ed process die correctly when released?
 * So far, we only test whether it zombifies - we need pdwait4() to reap it.
 */

static char getstate(int pid)
{
	char s[1024];
	char *prompt = "State:\t";
	char ret = '?';
	FILE *f;

	snprintf(s, sizeof(s), "/proc/%d/status", pid);
	f = fopen(s, "r");
	if (!f)
		return '\0';

	while (!feof(f)) {
		fgets(s, sizeof(s), f);
		if (!strncmp(s, prompt, strlen(prompt))) {
			ret = s[strlen(prompt)];
			break;
		}
	}
	fclose(f);
	return ret;
}

TEST_F(pdexit, release) {
	char state;
	int r = 0;

	state = getstate(self->pid);
	EXPECT_TRUE(state == 'R' || state == 'S');

	write(self->pipe, &r, sizeof(r));

	sleep(1);
	EXPECT_EQ(getstate(self->pid), 'Z');
}

/* The exit of a pdfork()ed process should not generate SIGCHLD. */

static void got_sigchld(int x)
{
	abort();
}

TEST_F(pdexit, no_signal) {
	int r = 0;

	signal(SIGCHLD, got_sigchld);
	write(self->pipe, &r, sizeof(r));
	waitpid(self->pid, &r, 0);
}

TEST_HARNESS_MAIN

