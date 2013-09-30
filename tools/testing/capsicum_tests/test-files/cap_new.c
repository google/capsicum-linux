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
#include <unistd.h>

#include "capsicum.h"

TEST(cap_new_basic) {
	int x = cap_new(STDOUT_FILENO, CAP_READ|CAP_WRITE|CAP_SEEK);
	EXPECT_NE(-1, x);
	write(x, "OK!\n", 4);
}

TEST(cap_enter_basic) {
	int rc = cap_enter();
	EXPECT_EQ(0, rc);
}


TEST_HARNESS_MAIN
