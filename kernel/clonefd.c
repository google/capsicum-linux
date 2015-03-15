/*
 * Support functions for CLONE_FD
 *
 * Copyright (c) 2015 Intel Corporation
 * Original authors: Josh Triplett <josh@joshtriplett.org>
 *                   Thiago Macieira <thiago@macieira.org>
 */
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include "clonefd.h"

static int clonefd_release(struct inode *inode, struct file *file)
{
	put_task_struct(file->private_data);
	return 0;
}

static unsigned int clonefd_poll(struct file *file, poll_table *wait)
{
	struct task_struct *p = file->private_data;
	poll_wait(file, &p->clonefd_wqh, wait);
	return p->exit_state ? (POLLIN | POLLRDNORM | POLLHUP) : 0;
}

static ssize_t clonefd_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct task_struct *p = file->private_data;
	int ret = 0;

	/* EOF after first read */
	if (*ppos)
		return 0;

	if (file->f_flags & O_NONBLOCK)
		ret = -EAGAIN;
	else
		ret = wait_event_interruptible(p->clonefd_wqh, p->exit_state);

	if (p->exit_state) {
		struct clonefd_info info = {};
		cputime_t utime, stime;
		task_exit_code_status(p->exit_code, &info.code, &info.status);
		info.code &= ~__SI_MASK;
		task_cputime(p, &utime, &stime);
		info.utime = cputime_to_clock_t(utime + p->signal->utime);
		info.stime = cputime_to_clock_t(stime + p->signal->stime);
		ret = simple_read_from_buffer(buf, count, ppos, &info, sizeof(info));
	}
	return ret;
}

static struct file_operations clonefd_fops = {
	.release = clonefd_release,
	.poll = clonefd_poll,
	.read = clonefd_read,
	.llseek = no_llseek,
};

/* Do process exit notification for clonefd. */
void clonefd_do_notify(struct task_struct *p)
{
	if (p->clonefd)
		wake_up_all(&p->clonefd_wqh);
}

/* Handle the CLONE_FD case for copy_process. */
int clonefd_do_clone(u64 clone_flags, struct task_struct *p,
		     struct clone4_args *args, struct clonefd_setup *setup)
{
	int flags;
	struct file *file;
	int fd;

	p->clonefd = !!(clone_flags & CLONE_FD);
	if (!p->clonefd)
		return 0;

	if (args->clonefd_flags & ~(O_CLOEXEC | O_NONBLOCK))
		return -EINVAL;

	init_waitqueue_head(&p->clonefd_wqh);

	get_task_struct(p);
	flags = O_RDONLY | FMODE_ATOMIC_POS | args->clonefd_flags;
	file = anon_inode_getfile("[process]", &clonefd_fops, p, flags);
	if (IS_ERR(file)) {
		put_task_struct(p);
		return PTR_ERR(file);
	}

	fd = get_unused_fd_flags(flags);
	if (fd < 0) {
		fput(file);
		return fd;
	}

	setup->fd = fd;
	setup->file = file;
	return 0;
}

/* Clean up clonefd information after a partially complete clone */
void clonefd_cleanup_failed_clone(struct clonefd_setup *setup)
{
	if (setup->file) {
		put_unused_fd(setup->fd);
		fput(setup->file);
	}
}

/* Finish setting up the clonefd */
void clonefd_install_fd(struct clone4_args *args, struct clonefd_setup *setup)
{
	if (setup->file) {
		fd_install(setup->fd, setup->file);
		put_user(setup->fd, args->clonefd);
	}
}
