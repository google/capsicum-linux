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
#include <linux/capsicum-capmode.h>

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
static int capsicum_show_fdinfo(struct seq_file *m, struct file *capf);

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

/* Takes ownership of rights->ioctls */
static int capsicum_rights_limit(unsigned int fd,
				 struct capsicum_rights *rights)
{
	int rc = -EBADF;
	struct capsicum_capability *cap;
	struct file *capf = NULL;
	struct file *file;  /* current file for fd */
	struct file *underlying; /* base file for capability */
	struct files_struct *files = current->files;
	struct fdtable *fdt;

	/* Allocate capability before taking files->file_lock */
	capf = capsicum_cap_alloc(rights, true);
	rights->ioctls = NULL;  /* capsicum_cap_alloc took ownership */
	if (IS_ERR(capf))
		return PTR_ERR(capf);
	cap = capf->private_data;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_err;
	file = fdt->fd[fd];
	if (!file)
		goto out_err;

	/* If we're limiting an existing Capsicum capability object, ensure
	 * we wrap its underlying normal file. */
	if (capsicum_is_cap(file)) {
		struct capsicum_capability *old_cap = file->private_data;
		/* Reject attempts to widen existing rights */
		if (!cap_rights_contains(&old_cap->rights, &cap->rights)) {
			rc = -ENOTCAPABLE;
			goto out_err;
		}
		underlying = old_cap->underlying;
	} else {
		underlying = file;
	}
	if (!atomic_long_inc_not_zero(&underlying->f_count)) {
		rc = -EBADF;
		goto out_err;
	}
	cap->underlying = underlying;

	fput(file);
	rcu_assign_pointer(fdt->fd[fd], capf);
	spin_unlock(&files->file_lock);
	return 0;
out_err:
	spin_unlock(&files->file_lock);
	fput(capf);
	return rc;
}

SYSCALL_DEFINE5(cap_rights_limit,
		unsigned int, fd,
		const struct cap_rights __user *, new_rights,
		unsigned int, new_fcntls,
		int, nioctls,
		unsigned int __user *, new_ioctls)
{
	struct capsicum_rights rights;

	if (!new_rights)
		return -EFAULT;
	if (nioctls < 0 && nioctls != -1)
		return -EINVAL;
	if (copy_from_user(&rights.primary, new_rights,
			   sizeof(struct cap_rights)))
		return -EFAULT;
	rights.fcntls = new_fcntls;
	rights.nioctls = nioctls;
	if (rights.nioctls > 0) {
		size_t size;
		if (!new_ioctls)
			return -EINVAL;
		size = rights.nioctls * sizeof(unsigned int);
		rights.ioctls = kmalloc(size, GFP_KERNEL);
		if (!rights.ioctls)
			return -ENOMEM;
		if (copy_from_user(rights.ioctls, new_ioctls, size)) {
			kfree(rights.ioctls);
			return -EFAULT;
		}
	} else {
		rights.ioctls = NULL;
	}
	if (cap_rights_regularize(&rights))
		return -ENOTCAPABLE;

	return capsicum_rights_limit(fd, &rights);
}

SYSCALL_DEFINE5(cap_rights_get,
		unsigned int, fd,
		struct cap_rights __user *, rightsp,
		unsigned int __user *, fcntls,
		int __user *, nioctls,
		unsigned int __user *, ioctls)
{
	int result = -EFAULT;
	struct file *file;
	struct capsicum_rights *rights = &all_rights;
	int ioctls_to_copy = -1;

	file = fget(fd);
	if (file == NULL)
		return -EBADF;
	if (capsicum_is_cap(file)) {
		struct capsicum_capability *cap = file->private_data;
		rights = &cap->rights;
	}

	if (rightsp) {
		if (copy_to_user(rightsp, &rights->primary,
				 sizeof(struct cap_rights)))
			goto out;
	}
	if (fcntls) {
		if (put_user(rights->fcntls, fcntls))
			goto out;
	}
	if (nioctls) {
		int n;
		if (get_user(n, nioctls))
			goto out;
		if (put_user(rights->nioctls, nioctls))
			goto out;
		ioctls_to_copy = min(rights->nioctls, n);
	}
	if (ioctls && ioctls_to_copy > 0) {
		if (copy_to_user(ioctls, rights->ioctls,
				 ioctls_to_copy * sizeof(unsigned int)))
			goto out;
	}
	result = 0;
out:
	fput(file);
	return result;
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

static int capsicum_show_fdinfo(struct seq_file *m, struct file *capf)
{
	int i;
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return -EINVAL;

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
	return 0;
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
 * LSM hook fallback functions.
 */

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

	if (!atomic_long_inc_not_zero(&file->f_count)) {
		fput(capf);
		return ERR_PTR(-EBADF);
	}
	cap = capf->private_data;
	cap->underlying = file;
	return capf;
}
EXPORT_SYMBOL(capsicum_file_install);

#else

struct file *capsicum_file_lookup(struct file *file,
				  const struct capsicum_rights *required_rights,
				  const struct capsicum_rights **actual_rights)
{
	return file;
}

struct file *
capsicum_file_install(const const struct capsicum_rights *base_rights,
		      struct file *file)
{
	return file;
}

#endif
