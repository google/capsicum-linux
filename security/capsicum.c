/*
 * Linux implementation of Capsicum, a capability API for UNIX.
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
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/security.h>

#include "capsicum_int.h"

/*
 * Capsicum consists of:
 *
 *  - A "capability", which is a struct file which wraps an underlying
 *    struct file, with some permissions. Direct operations on this
 *    object are an error - it should be unwrapped (and access checks
 *    performed) before anyone tries to do anything with it.
 *  - An LSM hook which allows us transparently intercept the return value
 *    of fget(), so we can check permissions and return the actual
 *    underlying file object.
 *  - (TODO) A seccomp mode which checks all system calls against a table,
 *    and determines whether they have the appropriate rights for any
 *    capability-wrapped file descriptors they're operating on.
 *  - (TODO) A hook (not necessarily LSM) to prevent upward directory
 *    traversal when using openat() and friends in capability mode.
 *  - (TODO) A "process descriptor" mechanism which allows processes to
 *    refer to each other with file descriptors, which can then be
 *    capability-wrapped, allowing us to restrict access to the global PID
 *    namespace.
 */

struct capability {
	u64 rights;
	struct file *underlying;
};

extern const struct file_operations capability_ops;
static struct security_operations capsicum_security_ops;

static int __init capsicum_init(void)
{
	if (security_module_enable(&capsicum_security_ops)) {
		pr_debug("Capsicum enabled\n");
		register_security(&capsicum_security_ops);
	}
	return 0;
}
__initcall(capsicum_init);


int capsicum_is_cap(const struct file *file)
{
	return file->f_op == &capability_ops;
}

/*
 * Create a capability-wrapped file with the given rights. If orig is already
 * wrapped, then return a new wrapped file that refers to the underlying
 * object. Returns the fd number.
 */
int capsicum_wrap_new_fd(struct file *orig, u64 rights)
{
	int fd;
	struct capability *cap;

	if (capsicum_is_cap(orig))
		orig = capsicum_unwrap(orig, NULL);
	cap = kmalloc(sizeof(*cap), GFP_KERNEL);
	if (cap == NULL)
		return -ENOMEM;
	cap->rights = rights;
	cap->underlying = orig;
	get_file(orig);

	fd = anon_inode_getfd("[capability]", &capability_ops, cap, 0);
	if (fd < 0) {
		kfree(cap);
		fput(orig);
	}

	return fd;
}

/*
 * Given a capability, return the underlying file wrapped by that capability.
 * If rights is non-NULL, the capability's rights will be stored there too.
 * If cap is not a capability, returns NULL.
 */
struct file *capsicum_unwrap(const struct file *cap, u64 *rights)
{
	struct capability *c;

	if (!capsicum_is_cap(cap))
		return NULL;

	c = cap->private_data;

	if (rights)
		*rights = c->rights;

	return c->underlying;
}

/*
 * When we release a capability, release our reference to the underlying
 * (wrapped) file as well.
 */
static int capsicum_release(struct inode *i, struct file *fp)
{
	struct capability *c;

	if (!capsicum_is_cap(fp))
		return -EINVAL;

	c = fp->private_data;
	fput(c->underlying);
	kfree(c);

	return 0;
}

static struct file *capsicum_file_lookup(struct file *file, unsigned int fd)
{
	/* TODO(meredydd) unwrapping is currently unconditional. This needs
	 * fixing.
	 */
	struct file *unwrapped = capsicum_unwrap(file, NULL);
	if (unwrapped != NULL)
		file = unwrapped;

	return file;
}

static void panic_not_unwrapped(void)
{
	panic("Called a file_operations member on a Capsicum wrapper");
}

#define panic_ptr ((void *)&panic_not_unwrapped)

const struct file_operations capability_ops = {
	.owner = NULL,
	.llseek = panic_ptr,
	.read = panic_ptr,
	.write = panic_ptr,
	.aio_read = panic_ptr,
	.aio_write = panic_ptr,
	.readdir = panic_ptr,
	.poll = panic_ptr,
	.unlocked_ioctl = panic_ptr,
	.compat_ioctl = panic_ptr,
	.mmap = panic_ptr,
	.open = panic_ptr,
	.flush = NULL,  /* This one is called on close if implemented. */
	.release = capsicum_release, /* This is the only one we want. */
	.fsync = panic_ptr,
	.aio_fsync = panic_ptr,
	.fasync = panic_ptr,
	.lock = panic_ptr,
	.sendpage = panic_ptr,
	.get_unmapped_area = panic_ptr,
	.check_flags = panic_ptr,
	.flock = panic_ptr,
	.splice_write = panic_ptr,
	.splice_read = panic_ptr,
	.setlease = panic_ptr
};

static struct security_operations capsicum_security_ops = {
		.name = "capsicum",
		.file_lookup = capsicum_file_lookup
};
