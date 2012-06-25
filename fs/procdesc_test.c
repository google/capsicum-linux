/*
 * Kernel-space unit tests for process descriptor support.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/procdesc.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <misc/test_harness.h>

#include "procdesc_int.h"

/* Hack in prototypes. */
SYSCALL_DEFINE3(pdfork, int __user *, fdp, int, flags, struct pt_regs *, regs);


/* These tests can spawn child processes. This doesn't matter, because
 * the launch environment for these kernel tests immediately exits.
 * More sophisticated tests which require cooperation from the child
 * process must run from userspace.
 */

TEST(pd_create) {
	int r, fd = -1;
	struct file *f;
	struct task_struct *p;

	r = sys_pdfork(&fd, 0, task_pt_regs(current));
	EXPECT_GE(r, 0);

	/* We can't get a return value for FD, because it's a userspace pointer
	 * parameter. But we happen to know that it will be #4.
	 */

	f = fget(4);
	ASSERT_TRUE(f != NULL);
	ASSERT_TRUE(file_is_procdesc(f));
	p = FILE_PD(f)->task;
	EXPECT_EQ(p->pid, r);
	fput(f);
}

TEST_HARNESS_DEBUGFS_TRIGGER(procdesc)
