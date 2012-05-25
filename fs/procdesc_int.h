/*
 * Temporary internal definitions for process descriptor support.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#ifndef __PROCDESC_INT_H__
#define __PROCDESC_INT_H__

extern const struct file_operations procdesc_ops;

/* This structure will need expansion later (eg to hold the PD_DAEMON flag). */
struct procdesc {
	struct task_struct *task;
};
#define FILE_PD(f) ((struct procdesc *)((f)->private_data))

#endif /* __PROCDEC_INT_H__ */
