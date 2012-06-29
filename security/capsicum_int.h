/*
 * Temporary internal definitions for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#ifndef __CAPSICUM_INT_H__
#define __CAPSICUM_INT_H__

#include <linux/file.h>
#include "capsicum_caps.h"

/* This is used in seccomp.c; eventually it should move to a public location. */
struct capsicum_pending_syscall *capsicum_get_pending_syscall(void);

/* Everything else in this file is for use in test code only
 * (capsicum_test.c).
 */

int capsicum_is_cap(const struct file *file);
int capsicum_wrap_new_fd(struct file *orig, u64 rights);
struct file *capsicum_unwrap(const struct file *capability, u64 *rights);
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);
int capsicum_run_syscall_table(int arch, int call, unsigned long *args);

/* Per-thread Capsicum local state. We use this to check that file mappings
 * haven't changed between calls to our hooks, to prevent a time-of-check/
 * time-of-use race.
 */
struct capsicum_pending_syscall {
	struct file *files[6];
	struct file *next_new_cap;
	u64 new_cap_rights;
	unsigned int fds[6];
	int next_free;
	/* The back-reference to the task-struct allows us to detect when
	 * the cred struct gets shared between tasks, and un-share it.
	 */
	struct task_struct *task;
};

static inline bool capsicum_current_cap_mode(void)
{
	return test_thread_flag(TIF_SECCOMP) &&
			current->seccomp.mode == SECCOMP_MODE_CAPSICUM;
}

#endif /* __CAPSICUM_INT_H__ */
