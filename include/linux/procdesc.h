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

#define PD_DAEMON 0x1

#ifdef __KERNEL__
struct file *prepare_procdesc(void);
void set_procdesc_task(struct file *pd, struct task_struct *task, bool daemon);
bool file_is_procdesc(struct file *f);
#endif

#endif /* _LINUX_PROCDESC_H */
