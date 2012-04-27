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
#include <errno.h>

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
	printf("%d\n", x);

	r = write(x, "", 0);
	EXPECT_EQ(r, 0);
}


TEST_HARNESS_MAIN


