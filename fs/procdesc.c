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
#include <linux/file.h>
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

void set_procdesc_task(struct file *f, struct task_struct *task, bool daemon)
{
	BUG_ON(!file_is_procdesc(f));
	FILE_PD(f)->task = task;
	FILE_PD(f)->daemon = daemon;
}

bool file_is_procdesc(struct file *f)
{
	return f->f_op == &procdesc_ops;
}

SYSCALL_DEFINE2(pdgetpid, int, fd, pid_t __user *, pidp)
{
	struct file *pd;
	pid_t pid;

	pd = fget(fd);

	if (!pd)
		return -EBADF;
	if (!file_is_procdesc(pd)) {
		fput(pd);
		return -EINVAL;
	}

	pid = task_tgid_vnr(FILE_PD(pd)->task);
	fput(pd);
	put_user(pid, pidp);

	return 0;
}

long do_pdkill(struct task_struct *task, int signum)
{
	/* This is essentially the sys_kill call path, but with the permission
	 * checking removed. I've also removed the tasklist read lock, which
	 * I believe is only necessary for finding the process associated with
	 * a pid.
	 */
	struct siginfo info;

	info.si_signo = signum;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = task_tgid_vnr(current);
	info.si_uid = current_uid();

	return do_send_sig_info(signum, &info, task, true);
}

SYSCALL_DEFINE2(pdkill, int, fd, int, signum)
{
	struct file *pd;
	int ret;

	pd = fget(fd);

	if (!pd)
		return -EBADF;
	if (!file_is_procdesc(pd)) {
		fput(pd);
		return -EINVAL;
	}

	ret = do_pdkill(FILE_PD(pd)->task, signum);
	fput(pd);

	return ret;
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
		if (!pd->daemon && !task_is_dead(pd->task))
			do_pdkill(pd->task, SIGKILL);

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
