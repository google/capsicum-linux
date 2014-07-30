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

struct procdesc {
	struct task_struct *task;
	bool daemon;
};

static unsigned int procdesc_poll(struct file *f,
				  struct poll_table_struct *wait);
static int procdesc_release(struct inode *inode, struct file *f);
static int procdesc_show_fdinfo(struct seq_file *m, struct file *f);

static const struct file_operations procdesc_file_ops = {
	.poll = procdesc_poll,
	.release = procdesc_release,
	.show_fdinfo = procdesc_show_fdinfo
};

static inline bool file_is_procdesc(struct file *f)
{
	return f->f_op == &procdesc_file_ops;
}

/*
 * Retrieve the procdesc structure associated with a file, or NULL
 * if the file is not a process descriptor.
 */
static inline struct procdesc *procdesc_get(struct file *f)
{
	if (!f || !file_is_procdesc(f))
		return NULL;
	return f->private_data;
}

/* Allocate a new struct file and associated procdesc. */
struct file *procdesc_alloc(void)
{
	struct procdesc *pd;
	struct file *f;

	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	f = anon_new_inode_getfile("[procdesc]", &procdesc_file_ops, pd, 0);
	if (IS_ERR(f))
		kfree(pd);
	f->f_inode->i_mode = S_IRWXU;
	return f;
}

/* Initialize the contents of a previously-allocated procdesc structure. */
void procdesc_init(struct file *f, struct task_struct *task, bool daemon)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	pd->task = task;
	pd->daemon = daemon;
}

void procdesc_exit(struct task_struct *task)
{
	struct file *f = task->pd;
	if (f)
		f->f_inode->i_mode = 0;
}

SYSCALL_DEFINE2(pdgetpid, int, fd, pid_t __user *, pidp)
{
	struct file *f;
	struct procdesc *pd;
	pid_t pid;

	f = fgetr(fd, CAP_PDGETPID);
	if (IS_ERR(f))
		return PTR_ERR(f);

	pd = procdesc_get(f);
	if (!pd) {
		fput(f);
		return -EINVAL;
	}

	pid = task_tgid_vnr(pd->task);
	fput(f);
	put_user(pid, pidp);
	return 0;
}

static long do_pdkill(struct task_struct *task, int signum)
{
	/*
	 * This is essentially the sys_kill call path, but with the permission
	 * checking removed. I've also removed the tasklist read lock, which
	 * I believe is only necessary for finding the process associated with
	 * a pid.
	 */
	struct siginfo info;

	info.si_signo = signum;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = task_tgid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	return do_send_sig_info(signum, &info, task, true);
}

SYSCALL_DEFINE2(pdkill, int, fd, int, signum)
{
	struct file *f;
	struct procdesc *pd;
	int ret;

	f = fgetr(fd, CAP_PDKILL);
	if (IS_ERR(f))
		return PTR_ERR(f);

	pd = procdesc_get(f);
	if (!pd) {
		fput(f);
		return -EINVAL;
	}
	ret = do_pdkill(pd->task, signum);
	fput(f);
	return ret;
}

SYSCALL_DEFINE4(pdwait4, int, fd, int __user *, status, int, options,
		struct rusage __user *, rusage)
{
	struct file *f;
	struct procdesc *pd;
	pid_t pid;

	f = fgetr(fd, CAP_PDWAIT);
	if (IS_ERR(f))
		return PTR_ERR(f);

	/* Convert to a pid_t and forward on to wait4(2) */
	pd = procdesc_get(f);
	if (!pd) {
		fput(f);
		return -EINVAL;
	}
	pid = task_tgid_vnr(pd->task);
	fput(f);
	return sys_wait4(pid, status, options, rusage);
}

/*
 * File operations for process descriptor pseudofiles.
 */
static int procdesc_release(struct inode *inode, struct file *f)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	if (pd->task) {
		pd->task->pd = NULL;
		if (!pd->daemon && (pd->task->exit_state == 0))
			do_pdkill(pd->task, SIGKILL);

		BUG_ON(atomic_read(&pd->task->usage) < 1);
		put_task_struct(pd->task);
	}
	kfree(pd);
	return 0;
}

static unsigned int procdesc_poll(struct file *f,
				  struct poll_table_struct *wait)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	poll_wait(f, &pd->task->wait_exit, wait);

	if (pd->task->exit_state != 0)
		return POLLHUP;
	else
		return 0;
}

static int procdesc_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct procdesc *pd = procdesc_get(f);
	pid_t pid;

	if (!pd)
		return -EINVAL;

	pid = task_tgid_vnr(pd->task);
	seq_printf(m, "pid:\t%d\n", pid);
	return 0;
}
