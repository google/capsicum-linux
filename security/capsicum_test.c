/*
 * Kernel-space unit tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/file.h>

#include "capsicum_int.h"

#include "test_harness.h"

/*
 * These unit tests exercise the Capsicum security module.
 */

FIXTURE(new_cap) {
	struct file *orig;
	struct file *cap;
};

FIXTURE_SETUP(new_cap) {
	self->orig = fget(0);
	ASSERT_NE(self->orig, NULL);
	self->cap = capsicum_wrap_new(self->orig, 0);
}

FIXTURE_TEARDOWN(new_cap) {
	fput(self->orig);
	fput(self->cap);
}

TEST_F(new_cap, init_ok) {
	u64 rights = -1;
	struct file *f;

	EXPECT_GT(file_count(self->orig), 1);
	EXPECT_EQ(file_count(self->cap), 1);

	EXPECT_NE(self->cap, NULL);
	f = capsicum_unwrap(self->cap, &rights);
	EXPECT_EQ(rights, 0);
	EXPECT_EQ(f, self->orig);
}

TEST_F(new_cap, rewrap) {
	struct file *f, *uw;
	u64 rights;

	int old_count = file_count(self->orig);

	f = capsicum_wrap_new(self->cap, -1);

	uw = capsicum_unwrap(f, &rights);
	EXPECT_EQ(rights, -1);
	EXPECT_EQ(uw, self->orig);

	EXPECT_EQ(file_count(self->orig), old_count + 1);

	fput(f);

	EXPECT_EQ(file_count(self->orig), old_count);
}

TEST_F(new_cap, is_cap) {
	EXPECT_TRUE(capsicum_is_cap(self->cap));
	EXPECT_FALSE(capsicum_is_cap(self->orig));
}


/*
 * Below here are the debugfs shims to trigger tests by name.
 */


static ssize_t run_test_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char test[128];

	size_t s = min_t(size_t, count, 127);

	copy_from_user(test, ubuf, s);
	test[s] = '\0';
	if (s > 0 && test[s-1] == '\n')
		test[s-1] = '\0';

	printk(KERN_DEBUG "Running tests beginning with '%s':\n", test);
	test_harness_run(test);

	return count;
}

static struct file_operations fops;

static int __init capsicum_test_init(void)
{
	printk(KERN_DEBUG "capsicum_test_init()");

	fops = debugfs_file_operations;
	fops.write = run_test_write;

	debugfs_create_file("run_capsicum_tests", 0644, NULL,
		NULL, &fops);

	return 0;
}
__initcall(capsicum_test_init);


