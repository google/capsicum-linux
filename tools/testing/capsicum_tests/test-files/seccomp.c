/*
 * Tests for Capsicum, a capability API for UNIX.
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

#include "capsicum.h"

TEST(basic_interception) {
	int x = cap_new(1, 0);

	int r = write(x, "", 0);
	EXPECT_EQ(r, 0);

	cap_enter();

	r = write(x, "", 0);
	EXPECT_EQ(r, -1);
	EXPECT_EQ(errno, ENOTCAPABLE);

	x = cap_new(1, CAP_WRITE|CAP_SEEK);

	r = write(x, "", 0);
	EXPECT_EQ(r, 0);
}

TEST(directory_traversal) {
	int dir, file;

	dir = open("/tmp", O_RDONLY);
	ASSERT_GE(dir, 0);

	cap_enter();

	file = openat(dir, "testfile", O_RDONLY|O_CREAT);
	EXPECT_GE(file, 0);

	/* Test that we are confined to /tmp, and cannot
	 * escape using absolute paths or ../.
	 */
	file = openat(dir, "../dev/null", O_RDONLY);
	EXPECT_EQ(file, -1);

	file = openat(dir, "..", O_RDONLY);
	EXPECT_EQ(file, -1);

	file = openat(dir, "/dev/null", O_RDONLY);
	EXPECT_EQ(file, -1);

	file = openat(dir, "/", O_RDONLY);
	EXPECT_EQ(file, -1);
}

TEST(inheritance) {
	int dir, dircap, file, result;
	char c;

	/* Create a capability on /tmp that does not allow CAP_SEEK,
	 * and check that this restriction is inherited through openat().
	 */
	dir = open("/tmp", O_RDONLY);
	ASSERT_GE(dir, 0);
	dircap = cap_new(dir, CAP_READ|CAP_WRITE);

	file = openat(dir, "testfile", O_WRONLY|O_CREAT);
	ASSERT_GE(file, 0);
	write(file, "TEST\n", 5);
	close(file);

	cap_enter();
	file = openat(dircap, "testfile", O_RDONLY);
	EXPECT_GE(file, 0);

	/* This should not be permitted, as read() requires CAP_SEEK. */
	result = read(file, &c, 1);
	EXPECT_EQ(result, -1);
	EXPECT_EQ(errno, ENOTCAPABLE);

	close(file);
}

TEST_HARNESS_MAIN


