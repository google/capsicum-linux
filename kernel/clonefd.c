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
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include "audit.h"
#include "clonefd.h"

struct clonefd_data {
	struct task_struct *task;
	u32 flags;
};

static int clonefd_task_kill(struct task_struct *task, __u8 signum)
{
	struct siginfo info;
	int error;

	if (!valid_signal(signum))
		return -EINVAL;

	info.si_signo = signum;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = task_tgid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	/* Let audit and LSM see the signal. */
	rcu_read_lock();
	error = audit_signal_info(signum, task);
	if (error)
		goto err_unlock;
	error = security_task_kill(task, &info, signum, 0);
	if (error)
		goto err_unlock;
	rcu_read_unlock();

	/*
	 * The task to be signalled is directly identified, so jump straight
	 * to the signaling part of normal kill(2) processing.
	 */
	return do_send_sig_info(signum, &info, task, true);

err_unlock:
	rcu_read_unlock();
	return error;
}

static ssize_t clonefd_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct clonefd_data *data = file->private_data;
	__u8 signum;

	if (copy_from_user(&signum, buf, sizeof(signum)))
		return -EFAULT;

	return clonefd_task_kill(data->task, signum) ?: sizeof(signum);
}

static int clonefd_release(struct inode *inode, struct file *file)
{
	struct clonefd_data *data = file->private_data;

	put_task_struct(data->task);
	kfree(data);
	return 0;
}

static unsigned int clonefd_poll(struct file *file, poll_table *wait)
{
	struct clonefd_data *data = file->private_data;
	struct task_struct *p = data->task;

	poll_wait(file, &p->clonefd_wqh, wait);
	return p->exit_state ? (POLLIN | POLLRDNORM | POLLHUP) : 0;
}

static ssize_t clonefd_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct clonefd_data *data = file->private_data;
	struct task_struct *p = data->task;
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
		ret = simple_read_from_buffer(buf, count, ppos,
					      &info, sizeof(info));
	}
	return ret;
}

static long clonefd_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct clonefd_data *data = file->private_data;
	struct task_struct *p = data->task;
	int ret = 0;

	switch (cmd) {
	case CLONEFD_IOC_GETTID: {
		ret = task_pid_vnr(p);
		break;
	}
	case CLONEFD_IOC_GETPID: {
		ret = task_tgid_vnr(p);
		break;
	}
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static void clonefd_show_fdinfo(struct seq_file *m, struct file *file)
{
	struct clonefd_data *data = file->private_data;
	struct task_struct *p = data->task;

	seq_printf(m, "pid:\t%d\ntid:\t%d\n",
		   task_pid_vnr(p), task_tgid_vnr(p));
}

static const struct file_operations clonefd_fops = {
	.release = clonefd_release,
	.poll = clonefd_poll,
	.read = clonefd_read,
	.llseek = no_llseek,
	.write = clonefd_write,
	.unlocked_ioctl = clonefd_ioctl,
	.compat_ioctl = clonefd_ioctl,
	.show_fdinfo = clonefd_show_fdinfo,
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
	struct clonefd_data *data;
	struct file *file;
	int fd;

	p->clonefd = !!(clone_flags & CLONE_FD);
	if (!p->clonefd)
		return 0;

	if (args->clonefd_flags & ~(CLONEFD_CLOEXEC | CLONEFD_NONBLOCK))
		return -EINVAL;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	data->flags = args->clonefd_flags;
	data->task = p;

	init_waitqueue_head(&p->clonefd_wqh);

	get_task_struct(p);
	flags = O_RDWR | FMODE_ATOMIC_POS;
	if (args->clonefd_flags & CLONEFD_CLOEXEC)
		flags |= O_CLOEXEC;
	if (args->clonefd_flags & CLONEFD_NONBLOCK)
		flags |= O_NONBLOCK;
	file = anon_inode_getfile("[process]", &clonefd_fops, data, flags);
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
		kfree(setup->file->private_data);
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
