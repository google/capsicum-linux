/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include "linux/file.h"
#include "linux/fs.h"
#include "linux/mm.h"
#include "linux/procdesc.h"
#include "linux/sched.h"
#include "linux/uaccess.h"
#include "linux/utsname.h"
#include "linux/syscalls.h"
#include "asm/current.h"
#include "asm/mman.h"
#include "asm/uaccess.h"
#include "asm/unistd.h"
#include "internal.h"

long sys_fork(void)
{
	long ret;

	current->thread.forking = 1;
	ret = do_fork(SIGCHLD, UPT_SP(&current->thread.regs.regs),
		      &current->thread.regs, 0, NULL,
		      NULL, NULL);
	current->thread.forking = 0;
	return ret;
}

long sys_vfork(void)
{
	long ret;

	current->thread.forking = 1;
	ret = do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD,
		      UPT_SP(&current->thread.regs.regs),
		      &current->thread.regs, 0, NULL,
		      NULL, NULL);
	current->thread.forking = 0;
	return ret;
}

long sys_pdfork(int __user *fdp, int flags)
{
#ifdef CONFIG_PROCDESC
	long ret;
	int fd;
	struct task_struct *task = NULL;
	struct file *pd;

	fd = get_unused_fd();
	if (fd < 0)
		return fd;

	pd = prepare_procdesc();
	if (IS_ERR(pd)) {
		ret = PTR_ERR(pd);
		goto out_putfd;
	}

	current->thread.forking = 1;
	ret = do_fork(0, UPT_SP(&current->thread.regs.regs),
		      &current->thread.regs, 0, &task, NULL, NULL);
	current->thread.forking = 0;

	if (ret < 0)
		goto out_fput;

	set_procdesc_task(pd, task);
	fd_install(fd, pd);
	put_user(fd, fdp);

	return ret;

out_fput:
	fput(pd);
out_putfd:
	put_unused_fd(fd);
	return ret;
#else
	return -ENOSYS;
#endif
}

long old_mmap(unsigned long addr, unsigned long len,
	      unsigned long prot, unsigned long flags,
	      unsigned long fd, unsigned long offset)
{
	long err = -EINVAL;
	if (offset & ~PAGE_MASK)
		goto out;

	err = sys_mmap_pgoff(addr, len, prot, flags, fd, offset >> PAGE_SHIFT);
 out:
	return err;
}

int kernel_execve(const char *filename,
		  const char *const argv[],
		  const char *const envp[])
{
	mm_segment_t fs;
	int ret;

	fs = get_fs();
	set_fs(KERNEL_DS);
	ret = um_execve(filename, (const char __user *const __user *)argv,
			(const char __user *const __user *) envp);
	set_fs(fs);

	return ret;
}
