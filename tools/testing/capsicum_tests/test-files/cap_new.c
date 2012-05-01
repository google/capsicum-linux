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

#include "capsicum.h"

TEST(cap_new_basic) {
	int x = cap_new(1, 0);

	write(x, "OK!\n", 4);
}

TEST(cap_enter_basic) {
	cap_enter();
}


TEST_HARNESS_MAIN


