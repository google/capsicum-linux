/*
 * Main implementation of Capsicum, a capability framework for UNIX.
 *
 * Copyright (C) 2012-2013 The Chromium OS Authors <chromium-os-dev@chromium.org>
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
#include <linux/procdesc.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/capsicum.h>

#ifdef CONFIG_SECURITY_CAPSICUM
/*
 * Capsicum capability structure, holding the associated rights and underlying
 * real file.  Capabilities are not stacked, i.e. underlying always points to a
 * normal file not another Capsicum capability. Stored in file->private_data.
 */
struct capsicum_capability {
	cap_rights_t rights;
	struct file *underlying;
};

extern struct file_operations capsicum_file_ops;

static inline bool capsicum_in_cap_mode(void)
{
	return test_thread_flag(TIF_SECCOMP) &&
			current->seccomp.mode == SECCOMP_MODE_LSM;
}

inline int capsicum_is_cap(const struct file *file)
{
	return file->f_op == &capsicum_file_ops;
}
EXPORT_SYMBOL(capsicum_is_cap);

/*
 * Allocate a Capsicum capability object to wrap a given file object
 * with the given rights.  Assumes the underlying file has already been
 * unwrapped, i.e. is a normal file not a Capsicum capability object.
 */
static struct file *capsicum_wrap(struct file *underlying, cap_rights_t rights)
{
	struct capsicum_capability *cap;
	struct file *capf;

	cap = kzalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap)
		return ERR_PTR(-ENOMEM);

	capf = anon_inode_getfile("[capability]", &capsicum_file_ops, cap, 0);
	if (IS_ERR(capf)) {
		kfree(cap);
		return capf;
	}

	if (!atomic_long_inc_not_zero(&underlying->f_count)) {
		fput(capf);
		return ERR_PTR(-EBADF);
	}
	cap->underlying = underlying;
	cap->rights = rights;
	return capf;
}

/*
 * Given a Capsicum capability object, return the underlying file wrapped by
 * that capability.  If rights is non-NULL, the capability's rights will be
 * stored there too.  If cap is not a capability, returns NULL.
 */
struct file *capsicum_unwrap(const struct file *capf, cap_rights_t *rights)
{
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return NULL;

	cap = capf->private_data;

	if (rights)
		*rights = cap->rights;

	return cap->underlying;
}
EXPORT_SYMBOL(capsicum_unwrap);

/* Include the per-syscall processing code */
#include "capsicum_syscall_table.h"

int capsicum_rights_limit(unsigned int fd, cap_rights_t *new_rights)
{
	int rc = -EBADF;
	struct file *capf = NULL;
	struct file *file;  /* current file for fd */
	struct file *underlying;  /* base file for capability */
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	cap_rights_t existing_rights = CAP_ALL;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_err;
	file = fdt->fd[fd];
	if (!file)
		goto out_err;

	/* If we're limiting an existing Capsicum capability object, ensure
	 * we wrap its underlying normal file. */
	underlying = capsicum_unwrap(file, &existing_rights);
	if (!underlying)
		underlying = file;

	/* Reject attempts to widen rights */
	if (((*new_rights) & existing_rights) != (*new_rights)) {
		rc = -ENOTCAPABLE;
		goto out_err;
	}

	capf = capsicum_wrap(underlying, *new_rights);
	if (IS_ERR(capf)) {
		rc = PTR_ERR(capf);
		goto out_err;
	}

	fput(file);
	rcu_assign_pointer(fdt->fd[fd], capf);
	spin_unlock(&files->file_lock);
	return 0;

out_err:
	spin_unlock(&files->file_lock);
	return rc;
}
EXPORT_SYMBOL(capsicum_rights_limit);

SYSCALL_DEFINE2(cap_rights_limit, unsigned int, fd, const u64 __user *, new_rights)
{
	cap_rights_t rights;

	if (!new_rights)
		return -EFAULT;
	if (copy_from_user(&rights, new_rights, sizeof(cap_rights_t)))
		return -EFAULT;

	return capsicum_rights_limit(fd, &rights);
}

SYSCALL_DEFINE2(cap_rights_get, unsigned int, fd, u64 __user *, rightsp)
{
	int result;
	struct file *file;
	struct files_struct *files = current->files;
        cap_rights_t rights = CAP_ALL;

	rcu_read_lock();
	file = fcheck_files(files, fd);

	if (!file) {
		result = -EBADF;
		goto out_err;
	}

	if (capsicum_unwrap(file, &rights) == NULL) {
		result = -EINVAL;
		goto out_err;
	}
	rcu_read_unlock();
	put_user(rights, rightsp);
	return 0;

out_err:
	rcu_read_unlock();
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
	kfree(cap);
	return 0;
}

static int capsicum_show_fdinfo(struct seq_file *m, struct file *capf)
{
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return -EINVAL;

	cap = capf->private_data;
	BUG_ON(!cap);
	seq_printf(m, "rights:\t%#016llx\n", cap->rights);
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
 * Entrypoint to process an incoming syscall.
 * Returns 0 if the syscall should proceed, < 0 otherwise.
 */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	return capsicum_run_syscall_table(arch, callnr, args);
}
EXPORT_SYMBOL(capsicum_intercept_syscall);

/*
 * We are looking up a file by its file descriptor. If it is a Capsicum
 * capability, and has the required rights, we unwrap it and return the
 * underlying file.
 *
 * If we were in capability mode and this call was triggered by a syscall, we
 * performed a rights check on entry to the syscall. This function checks that
 * the file we are unwrapping is the same as the one which was examined in
 * capsicum_intercept_syscall().
 */
struct file *capsicum_file_lookup(struct file *file,
				  cap_rights_t required_rights,
				  cap_rights_t *actual_rights)
{
	cap_rights_t rights;
	struct file *underlying;

	/* See if the file in question is a Capsicum capability. */
	underlying = capsicum_unwrap(file, &rights);
	if (!underlying) {
		if (actual_rights)
			*actual_rights = CAP_ALL;
		return file;
	}
	if ((rights & required_rights) != required_rights)
		return ERR_PTR(-ENOTCAPABLE);
	if (actual_rights)
		*actual_rights = rights;
	return underlying;
}
EXPORT_SYMBOL(capsicum_file_lookup);

struct file *capsicum_file_install(cap_rights_t base_rights, struct file *file)
{
	if (base_rights == CAP_ALL)
		return file;
	return capsicum_wrap(file, base_rights);
}
EXPORT_SYMBOL(capsicum_file_install);

#ifdef CONFIG_SECURITY_PATH
/*
 * Prevent absolute lookups and upward traversal (../) when in capability
 * mode or when the lookup is relative to a capability file descriptor.
 */
int capsicum_path_lookup(cap_rights_t base_rights,
			 struct dentry *dentry, const char *name)
{
	if (!capsicum_in_cap_mode() && base_rights == CAP_ALL)
		return 0;

	if (name[0] == '.' && name[1] == '.' &&
			(name[2] == '\0' || name[2] == '/'))
		return -ENOTCAPABLE;

	if (name[0] == '/')
		return -ENOTCAPABLE;

	return 0;
}
EXPORT_SYMBOL(capsicum_path_lookup);
#endif

#define panic_ptr ((void *)&capsicum_panic_not_unwrapped)
struct file_operations capsicum_file_ops = {
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
	.flush = NULL,  /* This one is called on close if implemented. */
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

#else

/* If Capsicum is not enabled, all the fallback LSM hooks return OK */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	return 0;
}

struct file *capsicum_file_lookup(struct file *file,
				  cap_rights_t required_rights,
				cap_rights_t *actual_rights)
{
	return file;
}

struct file *capsicum_file_install(cap_rights_t base_rights, struct file *file)
{
	return file;
}

#ifdef CONFIG_SECURITY_PATH
int capsicum_path_lookup(cap_rights_t base_rights,
			struct dentry *dentry, const char *name)
{
	return 0;
}
#endif

#endif
