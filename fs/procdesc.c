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
#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/procdesc.h>
#include <linux/resource.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

struct procdesc {
	struct task_struct *task;
	unsigned long flags;
};

static unsigned int procdesc_poll(struct file *f,
				  struct poll_table_struct *wait);
static int procdesc_release(struct inode *inode, struct file *f);
static void procdesc_show_fdinfo(struct seq_file *m, struct file *f);

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
void procdesc_init(struct file *f, struct task_struct *task,
		   unsigned long flags)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	pd->task = task;
	pd->flags = flags;
}

void procdesc_exit(struct task_struct *task)
{
	struct file *f;

	rcu_read_lock();
	f = task->procdesc;
	rcu_read_unlock();
	if (f)
		f->f_inode->i_mode = 0;
}

SYSCALL_DEFINE2(pdgetpid, int, fd, pid_t __user *, pidp)
{
	struct file *f;
	struct procdesc *pd;
	pid_t pid;

	f = fget(fd);
	if (!f)
		return -EBADF;

	pd = procdesc_get(f);
	if (!pd) {
		fput(f);
		return -EINVAL;
	}

	pid = task_tgid_vnr(pd->task);
	fput(f);
	if (pid == 0)
		return -ESRCH;
	put_user(pid, pidp);
	return 0;
}

#ifdef CONFIG_AUDITSYSCALL
extern int audit_pid;
extern int __audit_signal_info(int sig, struct task_struct *t);
static inline int audit_signal_info(int sig, struct task_struct *t)
{
	if (unlikely((audit_pid && t->tgid == audit_pid) ||
		     (audit_signals && !audit_dummy_context())))
		return __audit_signal_info(sig, t);
	return 0;
}
#else
#define audit_signal_info(s,t) 0
#endif

static long do_pdkill(struct task_struct *task, int signum)
{
	int error;
	struct siginfo info;

	info.si_signo = signum;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = task_tgid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	/* Let audit and LSM see the signal. */
	rcu_read_lock();
	error = audit_signal_info(signum, task);
	if (error)
		goto out_unlock;
	error = security_task_kill(task, &info, signum, 0);
	if (error)
		goto out_unlock;
	rcu_read_unlock();

	/*
	 * The task to be signalled is directly identified, so jump straight
	 * to the signaling part of normal kill(2) processing.
	 */
	return do_send_sig_info(signum, &info, task, true);

out_unlock:
	rcu_read_unlock();
	return error;
}

SYSCALL_DEFINE2(pdkill, int, fd, int, signum)
{
	struct file *f;
	struct procdesc *pd;
	int ret;

	if (!valid_signal(signum))
		return -EINVAL;

	f = fget(fd);
	if (!f)
		return -EBADF;

	pd = procdesc_get(f);
	if (!pd) {
		ret = -EINVAL;
		goto exit;
	}
	ret = do_pdkill(pd->task, signum);
exit:
	fput(f);
	return ret;
}

SYSCALL_DEFINE4(pdwait4, int, fd, int __user *, status, int, options,
		struct rusage __user *, rusage)
{
	struct file *f;
	struct procdesc *pd;
	pid_t pid;

	f = fget(fd);
	if (!f)
		return -EBADF;

	/* Convert to a pid_t and forward on to wait4(2) */
	pd = procdesc_get(f);
	if (!pd) {
		fput(f);
		return -EINVAL;
	}
	pid = task_tgid_vnr(pd->task);
	fput(f);
	if (pid == 0)
		return -ECHILD;
	return sys_wait4(pid, status, options, rusage);
}

/*
 * File operations for process descriptor pseudofiles.
 */
static int procdesc_release(struct inode *inode, struct file *f)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	BUG_ON(!pd->task);

	rcu_assign_pointer(pd->task->procdesc, NULL);

	if (!(pd->flags & PD_DAEMON) && (pd->task->exit_state == 0))
		do_pdkill(pd->task, SIGKILL);

	BUG_ON(atomic_read(&pd->task->usage) < 1);
	put_task_struct(pd->task);
	kfree(pd);
	return 0;
}

static unsigned int procdesc_poll(struct file *f,
				  struct poll_table_struct *wait)
{
	struct procdesc *pd = procdesc_get(f);

	BUG_ON(!pd);
	poll_wait(f, &pd->task->signal->wait_chldexit, wait);

	return (pd->task->exit_state != 0) ? POLLHUP : 0;
}

static void procdesc_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct procdesc *pd = procdesc_get(f);
	pid_t pid;

	if (!pd)
		return;
	pid = task_tgid_vnr(pd->task);
	seq_printf(m, "pid:\t%d\n", pid);
}
