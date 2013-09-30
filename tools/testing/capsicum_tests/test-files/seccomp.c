/*
 * Tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <uapi/asm-generic/errno.h>
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
	EXPECT_EQ(0, r);

	cap_enter();

	r = write(x, "", 0);
	EXPECT_EQ(-1, r);
	EXPECT_EQ(ENOTCAPABLE, errno);

	x = cap_new(1, CAP_WRITE|CAP_SEEK);

	r = write(x, "", 0);
	EXPECT_EQ(0, r);
}

TEST(directory_traversal) {
	int dir, file;

	dir = open("/tmp", O_RDONLY);
	ASSERT_LE(0, dir);

	cap_enter();

	file = openat(dir, "testfile", O_RDONLY|O_CREAT);
	EXPECT_LE(0, file);

	/* Test that we are confined to /tmp, and cannot
	 * escape using absolute paths or ../.
	 */
	file = openat(dir, "../dev/null", O_RDONLY);
	EXPECT_EQ(-1, file);

	file = openat(dir, "..", O_RDONLY);
	EXPECT_EQ(-1, file);

	file = openat(dir, "/dev/null", O_RDONLY);
	EXPECT_EQ(-1, file);

	file = openat(dir, "/", O_RDONLY);
	EXPECT_EQ(-1, file);
}

/*
 * Create a capability on /tmp that does not allow CAP_WRITE,
 * and check that this restriction is inherited through openat().
 */
TEST(inheritance) {
	int dir, dircap, file;

	dir = open("/tmp", O_RDONLY);
	ASSERT_LE(0, dir);
	dircap = cap_new(dir, CAP_READ|CAP_LOOKUP);

	char *fn = "testfile";
	file = openat(dir, fn, O_WRONLY|O_CREAT);
	ASSERT_LE(0, file);
	write(file, "TEST\n", 5);
	close(file);

	cap_enter();
	file = openat(dircap, "testfile", O_RDONLY);
	EXPECT_LE(0, file);
	if (file > 0)
		close(file);

	file = openat(dircap, "testfile", O_WRONLY|O_APPEND);
	EXPECT_EQ(-1, file);
	EXPECT_EQ(ENOTCAPABLE, errno);
	if (file > 0)
		close(file);
}

TEST_HARNESS_MAIN
