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

int capsicum_is_cap(const struct file *file);

struct file *capsicum_wrap_new(struct file *orig, u64 rights);

struct file *capsicum_unwrap(const struct file *capability, u64 *rights);

#endif /* __CAPSICUM_INT_H__ */

