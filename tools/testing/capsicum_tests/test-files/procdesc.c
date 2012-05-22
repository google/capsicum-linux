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

#include "procdesc.h"

TEST(use_pdfork) {
	int pd = -1, r;

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

TEST_HARNESS_MAIN

