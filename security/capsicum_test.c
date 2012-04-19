/*
 * Kernel-space unit tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors.
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

#include "capsicum_int.h"

#include "test_harness.h"


/*
 * Debugfs shims below here to trigger tests by name
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


