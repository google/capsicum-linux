/*
 * Support functions for CLONE_FD
 *
 * Copyright (c) 2015 Intel Corporation
 * Original authors: Josh Triplett <josh@joshtriplett.org>
 *                   Thiago Macieira <thiago@macieira.org>
 */
#pragma once

#include <linux/sched.h>
struct pid;

#ifdef CONFIG_CLONEFD
struct clonefd_setup {
	int fd;
	struct file *file;
};
int clonefd_do_clone(u64 clone_flags, struct task_struct *p,
		     struct clone4_args *args, struct clonefd_setup *setup);
void clonefd_cleanup_failed_clone(struct clonefd_setup *setup);
void clonefd_install_fd(struct clone4_args *args, struct clonefd_setup *setup);
void clonefd_do_notify(struct task_struct *p);
struct pid *clonefd_get_pid(int fd);
#else /* CONFIG_CLONEFD */
struct clonefd_setup {};
static inline int clonefd_do_clone(u64 clone_flags, struct task_struct *p,
				   struct clone4_args *args,
				   struct clonefd_setup *setup)
{
	return 0;
}
static inline void clonefd_cleanup_failed_clone(struct clonefd_setup *setup) {}
static inline void clonefd_install_fd(struct clone4_args *args,
				      struct clonefd_setup *setup) {}
static inline void clonefd_do_notify(struct task_struct *p) {}
static inline struct pid *clonefd_get_pid(int fd)
{
	return ERR_PTR(-EINVAL);
}
#endif /* CONFIG_CLONEFD */
