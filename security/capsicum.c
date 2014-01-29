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

#if 0
#define kdebug(FMT, ...) \
	printk(KERN_ERR "[%-9.9s%5u] "FMT"\n", current->comm, current->pid ,##__VA_ARGS__)
#else
#define kdebug(FMT, ...)
#endif

/*
 * Capsicum capability structure, holding the associated rights and underlying
 * real file.  Capabilities are not stacked, i.e. underlying always points to a
 * normal file not another capsicum_capability. Stored in file->private_data.
 */
struct capsicum_capability {
	cap_rights_t rights;
	struct file *underlying;
};

/* Whether the Capsicum LSM is enabled */
static int capsicum_enabled;

extern struct file_operations capsicum_file_ops;
extern struct security_operations capsicum_security_ops;

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
 * Allocate a Capsicum capability object.
 */
static struct file *capsicum_cap_alloc(void)
{
	struct capsicum_capability *cap;
	struct file *newfile;

	cap = kzalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap)
		return ERR_PTR(-ENOMEM);

	newfile = anon_inode_getfile("[capability]", &capsicum_file_ops, cap, 0);
	if (IS_ERR(newfile))
		kfree(cap);

	return newfile;
}

/*
 * Initialise an already-allocated Capsicum capability object. to point to the
 * given underlying file with the given rights.
 */
static void capsicum_cap_set(struct file *capf, struct file *underlying,
			cap_rights_t rights)
{
	struct capsicum_capability *cap = capf->private_data;

	BUG_ON(!capsicum_is_cap(capf));
	BUG_ON(!cap);
	cap->underlying = underlying;
	cap->rights = rights;
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

/*
 * Wrap a file in a new Capsicum capability object and install the capability
 * object into the file descriptor table.  Returns the new file descriptor or an
 * error.
 */
int capsicum_install_fd(struct file *orig, cap_rights_t rights)
{
	int error, fd;
	struct file *capf;
	struct file *file;

	error = get_unused_fd();
	if (error < 0)
		return error;
	fd = error;

	capf = capsicum_cap_alloc();
	if (IS_ERR(capf)) {
		error = PTR_ERR(capf);
		goto err_put_unused_fd;
	}

	file = capsicum_unwrap(orig, NULL);
	if (file)
		orig = file;
	get_file(orig);
	capsicum_cap_set(capf, orig, rights);
	fd_install(fd, capf);

	return fd;

err_put_unused_fd:
	put_unused_fd(fd);
	return error;
}
EXPORT_SYMBOL(capsicum_install_fd);

/* Include the per-syscall processing code */
#include "capsicum_syscall_table.h"

/*
 * Entrypoint to process an incoming syscall (from kernel/seccomp.c).
 * Returns 0 if the syscall should proceed, < 0 otherwise.
 */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	if (!capsicum_enabled)
		return 0;
	return capsicum_run_syscall_table(arch, callnr, args);
}

static int do_sys_cap_new(unsigned int orig_fd, cap_rights_t new_rights)
{
	struct file *file;
	struct files_struct *files = current->files;
	cap_rights_t existing_rights = CAP_ALL;

	rcu_read_lock();
	file = fcheck_files(files, orig_fd);

	if (!file)
		goto out_err;

	if (capsicum_is_cap(file)) {
		file = capsicum_unwrap(file, &existing_rights);
		if (!file)
			goto out_err;
	}

	if (!atomic_long_inc_not_zero(&file->f_count))
		goto out_err;

	rcu_read_unlock();
	return capsicum_install_fd(file, new_rights & existing_rights);

out_err:
	rcu_read_unlock();
	return -EBADF;
}

SYSCALL_DEFINE2(cap_new, unsigned int, orig_fd, u64, new_rights)
{
	if (!capsicum_enabled)
		return -ENOSYS;

	return do_sys_cap_new(orig_fd, (cap_rights_t)new_rights);
}

SYSCALL_DEFINE2(cap_getrights, unsigned int, fd, u64 __user *, rightsp)
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
 * LSM hook functions.
 */


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
static struct file *capsicum_file_lookup(struct file *file,
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


static struct file *capsicum_file_openat(cap_rights_t base_rights, struct file *file)
{
	cap_rights_t required_rights;
	struct file *capf;
	if (base_rights == CAP_ALL)
		return file;

	/* Now check the directory capability has the appropriate rights */
	required_rights = (file->f_flags & O_WRONLY) ? CAP_WRITE : CAP_READ;
	if (file->f_flags & O_RDWR)
		required_rights |= (CAP_READ|CAP_WRITE);
	if (file->f_flags & O_CREAT)
		required_rights |= CAP_WRITE;
	if (file->f_flags & O_EXCL)
		required_rights |= CAP_WRITE;
	if (file->f_flags & O_TRUNC)
		required_rights |= CAP_WRITE;

	if ((base_rights & required_rights) != required_rights)
		return ERR_PTR(-ENOTCAPABLE);

	/* Now allocate the Capsicum capability file wrapper */
	capf = capsicum_cap_alloc();
	if (IS_ERR(capf))
		return capf;

	capsicum_cap_set(capf, file, base_rights);
	return capf;
}

#ifdef CONFIG_SECURITY_PATH
/*
 * Prevent absolute lookups and upward traversal (../) when in capability
 * mode or when the lookup is relative to a capability file descriptor.
 */
static int capsicum_path_lookup(cap_rights_t base_rights,
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
#endif

static int __init capsicum_init(void)
{
	int err = register_security(&capsicum_security_ops);

	capsicum_enabled = !err;
	if (capsicum_enabled)
		printk(KERN_INFO "Capsicum enabled\n");
	else
		printk(KERN_WARNING "Capsicum enable failed: another security "
			"module has already been registered.\n");

	return 0;
}
__initcall(capsicum_init);

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

struct security_operations capsicum_security_ops = {
	.name = "capsicum",
	.intercept_syscall = capsicum_intercept_syscall,
	.file_lookup = capsicum_file_lookup,
	.file_openat = capsicum_file_openat,
#ifdef CONFIG_SECURITY_PATH
	.path_lookup = capsicum_path_lookup,
#endif
};
