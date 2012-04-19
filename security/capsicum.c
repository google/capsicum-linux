/*
 * Linux implementation of Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors.
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


static int __init capsicum_init(void)
{
	printk(KERN_DEBUG "capsicum_init()");
	return 0;
}
module_init(capsicum_init);
