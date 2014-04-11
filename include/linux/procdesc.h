/*
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#ifndef _LINUX_PROCDESC_H
#define _LINUX_PROCDESC_H

#include <uapi/linux/procdesc.h>

/* Allocate a process descriptor structure */
struct file *procdesc_alloc(void);
/* Initialize a process descriptor structure */
void procdesc_init(struct file *pd, struct task_struct *task,
		   unsigned long flags);
#ifdef CONFIG_PROCDESC
/* Notify associated process descriptor of task exit */
void procdesc_exit(struct task_struct *task);
#else
static inline void procdesc_exit(struct task_struct *task)
{
}
#endif

#endif /* _LINUX_PROCDESC_H */
