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

struct file *prepare_procdesc(void);
void set_procdesc_task(struct file *pd, struct task_struct *task);
bool file_is_procdesc(struct file *f);

#endif /* _LINUX_PROCDESC_H */
