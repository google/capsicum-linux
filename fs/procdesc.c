/*
 * Process descriptor support for Linux.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */
#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/procdesc.h>
#include <linux/resource.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "procdesc_int.h"

struct file *prepare_procdesc(void)
{
	struct procdesc *pd;
	struct file *f;

	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	f = anon_inode_getfile("[procdesc]", &procdesc_ops, pd, 0);
	if (IS_ERR(f))
		kfree(pd);

	return f;
}

void set_procdesc_task(struct file *f, struct task_struct *task)
{
	BUG_ON(!file_is_procdesc(f));
	FILE_PD(f)->task = task;
}

bool file_is_procdesc(struct file *f)
{
	return f->f_op == &procdesc_ops;
}

/* pdfork() is arch-specific. */

SYSCALL_DEFINE2(pdgetpid, int, fd, pid_t __user *, pidp)
{
	return -ENOSYS;
}

SYSCALL_DEFINE2(pdkill, int, fd, int, signum)
{
	return -ENOSYS;
}

SYSCALL_DEFINE4(pdwait4, int, fd, int __user *, status, int, options,
		struct rusage __user *, rusage)
{
	return -ENOSYS;
}

static int procdesc_release(struct inode *inode, struct file *file)
{
	struct procdesc *pd = FILE_PD(file);

	if (pd->task) {
		BUG_ON(atomic_read(&pd->task->usage) < 1);
		put_task_struct(pd->task);
	}
	kfree(pd);
	return 0;
}

static unsigned int procdesc_poll(struct file *file,
				   struct poll_table_struct *wait)
{
	struct procdesc *pd = FILE_PD(file);

	poll_wait(file, &pd->task->wait_exit, wait);

	if (task_is_dead(pd->task))
		return POLL_HUP;
	else
		return 0;
}

const struct file_operations procdesc_ops = {
	.poll = procdesc_poll,
	.release = procdesc_release
};
