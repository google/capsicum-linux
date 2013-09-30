/*
 * Part of a Linux implementation of Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <uapi/asm-generic/errno.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "capsicum.h"

static inline int sys_fexecve(int fd, char **argv, char **envp)
{
	return syscall(319, fd, argv, envp);
}

int myself;
char *argv_pass[] = {NULL, "--child", NULL};
char *argv_fail[] = {NULL, "--testfail", NULL};
char *child_envp[] = {NULL};

TEST(basic_fexecve) {
	int r;

	r = sys_fexecve(myself, argv_pass, child_envp);
	perror("fexecve");
	EXPECT_EQ(0, r);
	EXPECT_TRUE(!"fexecve() should never return");
}

TEST(fexecve_in_cap_mode) {
	int r;

	cap_enter();
	r = sys_fexecve(myself, argv_pass, child_envp);
	EXPECT_EQ(-1, r);
	EXPECT_EQ(ECAPMODE, errno);
}

TEST(fexecve_fails_without_cap) {
	int r, fd;

	cap_enter();
	fd = cap_new(myself, 0);
	r = sys_fexecve(fd, argv_fail, child_envp);
	EXPECT_EQ(-1, r);
	EXPECT_EQ(ENOTCAPABLE, errno);
}

TEST(fexecve_succeed_with_cap) {
	int r, fd;

	cap_enter();
	fd = cap_new(myself, CAP_FEXECVE);
	r = sys_fexecve(fd, argv_pass, child_envp);
	perror("fexecve()");
	EXPECT_EQ(0, r);
	EXPECT_TRUE(!"fexecve() should have succeeded");
}

TEST(fexecve_checks_permissions) {
	int result, fd;
	char buf[512];

	snprintf(buf, sizeof(buf),
		"cp %s %s.nonexec && chmod -x %s.nonexec",
		argv_pass[0], argv_pass[0], argv_pass[0]);
	result = system(buf);
	ASSERT_EQ(0, result);

	snprintf(buf, sizeof(buf), "%s.nonexec", argv_pass[0]);
	fd = open(buf, O_RDONLY);
	ASSERT_LE(0, fd);

	result = sys_fexecve(fd, argv_fail, child_envp);
	EXPECT_EQ(-1, result);
	EXPECT_EQ(EACCES, errno);

	close(fd);
}

TEST(execve_fails) {
	cap_enter();
	execve(argv_fail[0], argv_fail, child_envp);
	EXPECT_EQ(ECAPMODE, errno);
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
		if (!r)
			perror("exec() failed");
		return 1;
	}

	return test_harness_run(argc > 1 ? argv[1] : "");
}
