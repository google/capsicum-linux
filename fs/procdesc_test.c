/*
 * Kernel-space unit tests for process descriptor support.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <misc/test_harness.h>

#include "procdesc_int.h"


TEST_HARNESS_DEBUGFS_TRIGGER(procdesc)
