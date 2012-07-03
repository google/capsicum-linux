/*
 * Part of a Linux implementation of Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "capsicum.h"

static inline int sys_fexecve(int fd, char **argv, char **envp)
{
	return syscall(317, fd, argv, envp);
}

int myself;
char *argv_pass[] = {NULL, "--child", NULL};
char *argv_fail[] = {NULL, "--testfail", NULL};
char *child_envp[] = {NULL};

TEST(basic_fexecve) {
	int r;

	r = sys_fexecve(myself, argv_pass, child_envp);
	perror("fexecve");
	EXPECT_TRUE(!"fexecve() should never return");
}

TEST(fexecve_in_cap_mode) {
	int r;

	cap_enter();
	r = sys_fexecve(myself, argv_pass, child_envp);
	EXPECT_EQ(r, -1);
	EXPECT_EQ(errno, ECAPMODE);
}

TEST(fexecve_fails_without_cap) {
	int r, fd;

	cap_enter();
	fd = cap_new(myself, 0);
	r = sys_fexecve(fd, argv_fail, child_envp);
	EXPECT_EQ(r, -1);
	EXPECT_EQ(errno, ENOTCAPABLE);
}

TEST(fexecve_succeed_with_cap) {
	int r, fd;

	cap_enter();
	fd = cap_new(myself, CAP_FEXECVE);
	r = sys_fexecve(fd, argv_pass, child_envp);
	perror("fexecve()");
	EXPECT_TRUE(!"fexecve() should have succeeded");
}

TEST(fexecve_checks_permissions) {
	int result, fd;
	char buf[512];

	snprintf(buf, sizeof(buf),
		"cp %s %s.nonexec && chmod -x %s.nonexec",
		argv_pass[0], argv_pass[0], argv_pass[0]);
	result = system(buf);
	ASSERT_EQ(result, 0);

	snprintf(buf, sizeof(buf), "%s.nonexec", argv_pass[0]);
	fd = open(buf, O_RDONLY);
	ASSERT_GE(fd, 0);

	result = sys_fexecve(fd, argv_fail, child_envp);
	EXPECT_EQ(result, -1);
	EXPECT_EQ(errno, EACCES);

	close(fd);
}

TEST(execve_fails) {
	cap_enter();
	execve(argv_fail[0], argv_fail, child_envp);
	EXPECT_EQ(errno, ECAPMODE);
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--child"))
		exit(1);

	if (argc == 2 && !strcmp(argv[1], "--testfail"))
		exit(0);

	argv_pass[0] = argv_fail[0] = argv[0];
	myself = open(argv[0], O_RDONLY);
	if (myself == -1) {
		perror(argv[0]);
		exit(1);
	}

	if (argc == 2 && !strcmp(argv[1], "--self-exec")) {
		int r;

		cap_enter();
		r = sys_fexecve(myself, argv_pass, child_envp);
		perror("exec() failed");
		return 1;
	}

	return test_harness_run(argc > 1 ? argv[1] : "");
}


