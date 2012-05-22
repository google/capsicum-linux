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
#define FILE_IS_PROCDESC(f) ((f)->f_ops == procdesc_ops)

#endif /* __PROCDEC_INT_H__ */
