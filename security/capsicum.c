/*
 * Main implementation of Capsicum, a capability framework for UNIX.
 *
 * Copyright (C) 2012-2013 The Chromium OS Authors
 *                         <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * See Documentation/security/capsicum.txt for information on Capsicum.
 */

#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/capsicum.h>

#include "capsicum-rights.h"

#ifdef CONFIG_SECURITY_CAPSICUM
/*
 * Capsicum capability structure, holding the associated rights and underlying
 * real file.  Capabilities are not stacked, i.e. underlying always points to a
 * normal file not another Capsicum capability. Accessed via file->private_data.
 */
struct capsicum_capability {
	struct capsicum_rights rights;
	struct file *underlying;
};

static void capsicum_panic_not_unwrapped(void);
static int capsicum_release(struct inode *i, struct file *capf);
static void capsicum_show_fdinfo(struct seq_file *m, struct file *capf);

#define panic_ptr ((void *)&capsicum_panic_not_unwrapped)
static const struct file_operations capsicum_file_ops = {
	.owner = NULL,
	.llseek = panic_ptr,
	.read = panic_ptr,
	.write = panic_ptr,
	.aio_read = panic_ptr,
	.aio_write = panic_ptr,
	.iterate = panic_ptr,
	.poll = panic_ptr,
	.unlocked_ioctl = panic_ptr,
	.compat_ioctl = panic_ptr,
	.mmap = panic_ptr,
	.open = panic_ptr,
	.flush = NULL,  /* This is called on close if implemented. */
	.release = capsicum_release,  /* This is the only one we want. */
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
	.setlease = panic_ptr,
	.fallocate = panic_ptr,
	.show_fdinfo = capsicum_show_fdinfo
};

static inline bool capsicum_is_cap(const struct file *file)
{
	return file->f_op == &capsicum_file_ops;
}

static struct capsicum_rights all_rights = {
	.primary = {.cr_rights = {CAP_ALL0, CAP_ALL1} },
	.fcntls = CAP_FCNTL_ALL,
	.nioctls = -1,
	.ioctls = NULL
};

static struct file *capsicum_cap_alloc(const struct capsicum_rights *rights,
				       bool take_ioctls)
{
	int err;
	struct file *capf;
	/* memory to be freed on error exit: */
	struct capsicum_capability *cap = NULL;
	unsigned int *ioctls = (take_ioctls ? rights->ioctls : NULL);

	BUG_ON((rights->nioctls > 0) != (rights->ioctls != NULL));

	cap = kmalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap) {
		err = -ENOMEM;
		goto out_err;
	}
	cap->underlying = NULL;
	cap->rights = *rights;
	if (!take_ioctls && rights->nioctls > 0) {
		cap->rights.ioctls = kmemdup(rights->ioctls,
					rights->nioctls * sizeof(unsigned int),
					GFP_KERNEL);
		if (!cap->rights.ioctls) {
			err = -ENOMEM;
			goto out_err;
		}
		ioctls = cap->rights.ioctls;
	}

	capf = anon_inode_getfile("[capability]", &capsicum_file_ops, cap, 0);
	if (IS_ERR(capf)) {
		err = PTR_ERR(capf);
		goto out_err;
	}
	return capf;

out_err:
	kfree(ioctls);
	kfree(cap);
	return ERR_PTR(err);
}

/*
 * File operations functions.
 */

/*
 * When we release a Capsicum capability, release our reference to the
 * underlying (wrapped) file as well.
 */
static int capsicum_release(struct inode *i, struct file *capf)
{
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return -EINVAL;

	cap = capf->private_data;
	BUG_ON(!cap);
	if (cap->underlying)
		fput(cap->underlying);
	cap->underlying = NULL;
	kfree(cap->rights.ioctls);
	kfree(cap);
	return 0;
}

static void capsicum_show_fdinfo(struct seq_file *m, struct file *capf)
{
	int i;
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return;

	cap = capf->private_data;
	BUG_ON(!cap);
	seq_puts(m, "rights:");
	for (i = 0; i < (CAP_RIGHTS_VERSION + 2); i++)
		seq_printf(m, "\t%#016llx", cap->rights.primary.cr_rights[i]);
	seq_puts(m, "\n");
	seq_printf(m, " fcntls: %#08x\n", cap->rights.fcntls);
	if (cap->rights.nioctls > 0) {
		seq_puts(m, " ioctls:");
		for (i = 0; i < cap->rights.nioctls; i++)
			seq_printf(m, "\t%#08x", cap->rights.ioctls[i]);
		seq_puts(m, "\n");
	}
}

static void capsicum_panic_not_unwrapped(void)
{
	/*
	 * General Capsicum file operations should never be called, because the
	 * relevant file should always be unwrapped and the underlying real file
	 * used instead.
	 */
	panic("Called a file_operations member on a Capsicum wrapper");
}

/*
 * We are looking up a file by its file descriptor. If it is a Capsicum
 * capability, and has the required rights, we unwrap it and return the
 * underlying file.
 */
struct file *capsicum_file_lookup(struct file *file,
				  const struct capsicum_rights *required_rights,
				  const struct capsicum_rights **actual_rights)
{
	struct capsicum_capability *cap;

	/* See if the file in question is a Capsicum capability. */
	if (!capsicum_is_cap(file)) {
		if (actual_rights)
			*actual_rights = &all_rights;
		return file;
	}
	cap = file->private_data;
	if (required_rights &&
	    !cap_rights_contains(&cap->rights, required_rights)) {
		return ERR_PTR(-ENOTCAPABLE);
	}
	if (actual_rights)
		*actual_rights = &cap->rights;
	return cap->underlying;
}
EXPORT_SYMBOL(capsicum_file_lookup);

struct file *capsicum_file_install(const struct capsicum_rights *base_rights,
				   struct file *file)
{
	struct file *capf;
	struct capsicum_capability *cap;

	if (!base_rights || cap_rights_is_all(base_rights))
		return file;

	capf = capsicum_cap_alloc(base_rights, false);
	if (IS_ERR(capf))
		return capf;
	cap = capf->private_data;
	cap->underlying = file;
	return capf;
}
EXPORT_SYMBOL(capsicum_file_install);

#endif
