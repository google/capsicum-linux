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
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#include "capsicum_int.h"

#include "test_harness.h"

/*
 * These unit tests exercise the Capsicum security module.
 */


/* Test the wrapping and unwrapping of file descriptors in capabilities. */
FIXTURE(new_cap) {
	struct file *orig;
	int cap;
	struct file *capf;
};

FIXTURE_SETUP(new_cap) {
	self->orig = fget(0);
	ASSERT_NE(self->orig, NULL);
	self->cap = capsicum_wrap_new_fd(self->orig, 0);
	ASSERT_GE(self->cap, 0);
	/* The new capability fd must not be the same as the original (0) */
	ASSERT_NE(self->cap, 0);
	self->capf = fcheck(self->cap);
	ASSERT_NE(self->capf, NULL);
}

FIXTURE_TEARDOWN(new_cap) {
	fput(self->orig);
	sys_close(self->cap);
}

TEST_F(new_cap, init_ok) {
	u64 rights;
	struct file *f;

	EXPECT_GT(file_count(self->orig), 1);
	EXPECT_EQ(file_count(self->capf), 1);

	rights = (u64)-1;
	f = capsicum_unwrap(self->capf, &rights);
	/* Verify that the rights are as we set them in setup. */
	EXPECT_EQ(rights, 0);
	EXPECT_EQ(f, self->orig);
}

TEST_F(new_cap, rewrap) {
	/* When we wrap an fd in a capability, then wrap that second fd
	 * in another capability, the new capability will refer to the same
	 * original file, and the reference count of the original file
	 * will be incremented.
	 */
	struct file *f, *unwrapped_file;
	u64 rights;

	int old_count, fd;

	old_count = file_count(self->orig);

	fd = capsicum_wrap_new_fd(self->capf, -1);
	ASSERT_GT(fd, 0);
	f = fcheck(fd);

	unwrapped_file = capsicum_unwrap(f, &rights);
	EXPECT_EQ(rights, -1);
	EXPECT_EQ(unwrapped_file, self->orig);

	EXPECT_EQ(file_count(self->orig), old_count + 1);

	sys_close(fd);

	EXPECT_EQ(file_count(self->orig), old_count);
}

TEST_F(new_cap, is_cap) {
	EXPECT_TRUE(capsicum_is_cap(self->capf));
	EXPECT_FALSE(capsicum_is_cap(self->orig));
}


/* Test that the fget() family of functions unwraps capabilites correctly. */
FIXTURE(fget) {
	struct file *orig;
	int cap;

	int orig_refs;
};

FIXTURE_SETUP(fget) {
	self->orig = fget(0);
	self->orig_refs = file_count(self->orig);
	self->cap = capsicum_wrap_new_fd(self->orig, 0);
	ASSERT_EQ(file_count(self->orig), self->orig_refs+1);
	ASSERT_EQ(file_count(fcheck(self->cap)), 1);
}

FIXTURE_TEARDOWN(fget) {
	ASSERT_EQ(file_count(self->orig), self->orig_refs+1);
	sys_close(self->cap);
	ASSERT_EQ(file_count(self->orig), self->orig_refs);
	fput(self->orig);
	ASSERT_EQ(file_count(self->orig), self->orig_refs-1);
}

TEST_F(fget, fget) {
	struct file *f = fget(self->cap);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_light) {
	int fpn;
	struct file *f = fget_light(self->cap, &fpn);

	EXPECT_EQ(f, self->orig);
	EXPECT_FALSE(fpn);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
}

TEST_F(fget, fget_raw) {
	struct file *f = fget_raw(self->cap);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_raw_light) {
	int fpn;
	struct file *f = fget_raw_light(self->cap, &fpn);


	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(fpn, 0);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
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


