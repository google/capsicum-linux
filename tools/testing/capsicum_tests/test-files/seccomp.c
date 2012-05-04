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

TEST_HARNESS_MAIN


