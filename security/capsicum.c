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

#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/procdesc.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/syscalls.h>

#include "capsicum_int.h"

/*
 * Capsicum consists of:
 *
 *  - A "capability", which is a struct file which wraps an underlying
 *    struct file, with some permissions. Direct operations on this
 *    object are an error - it should be unwrapped (and access checks
 *    performed) before anyone tries to do anything with it.
 *  - An LSM hook which allows us transparently intercept the return
 *    value of fget(), so we can check permissions and return the actual
 *    underlying file object.
 *  - A seccomp mode which checks all system calls against a table, and
 *    determines whether they have the appropriate rights for any
 *    capability-wrapped file descriptors they're operating on.
 *  - An LSM hook to prevent upward directory traversal when using openat()
 *    and friends in capability mode.
 *  - (TODO) A "process descriptor" mechanism which allows processes to
 *    refer to each other with file descriptors, which can then be
 *    capability-wrapped, allowing us to restrict access to the global PID
 *    namespace.
 */

static int require_rights(unsigned long fd, u64 rights);

SYSCALL_DEFINE2(cap_new, unsigned int, orig_fd, u64, new_rights);

/* The table is generated code which uses require_rights() and sys_cap_new(),
 * so we include it here. We also include custom syscall handling code.
 */
#include "capsicum_custom_syscalls.h"
#include "capsicum_syscall_table.h"

struct capability {
	u64 rights;
	struct file *underlying;
};

static int enabled;

extern const struct file_operations capability_ops;
static struct security_operations capsicum_security_ops;

static int __init capsicum_init(void)
{
	int err = register_security(&capsicum_security_ops);

	enabled = !err;
	if (enabled)
		printk(KERN_INFO "Capsicum enabled\n");
	else
		printk(KERN_WARN "Capsicum enable failed: another security "
			"module has already been registered.\n");

	return 0;
}
__initcall(capsicum_init);

static int sys_cap_new_impl(unsigned int orig_fd, u64 new_rights)
{
	struct file *file;
	struct files_struct *files = current->files;
	u64 existing_rights = (u64)-1;

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
	return capsicum_wrap_new_fd(file, new_rights & existing_rights);

out_err:
	rcu_read_unlock();
	return -EBADF;
}

SYSCALL_DEFINE2(cap_new, unsigned int, orig_fd, u64, new_rights)
{
	if (!enabled)
		return -ENOSYS;

	return sys_cap_new_impl(orig_fd, new_rights);
}

int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	int result;
	struct capsicum_pending_syscall *pending;

	if (!enabled)
		return 0;

	pending = capsicum_get_pending_syscall();
	if (IS_ERR(pending))
		return PTR_ERR(pending);

	pending->next_free = 0;
	pending->new_cap_rights = 0;
	result = capsicum_run_syscall_table(arch, callnr, args);

	/* TODO(meredydd) custom syscalls here */

	return result;
}

static int require_rights(unsigned long fd, u64 required_rights)
{
	struct file *file;
	u64 actual_rights = (u64)-1;
	int result = -1;
	struct capsicum_pending_syscall *pending;

	/* AT_FDCWD is a non-file-descriptor value passed in a file-descriptor
	 * parameter to openat() and friends, to make them act like open() and
	 * friends. This is not permitted in cap mode, where every path lookup
	 * must be governed by a capability, so we provide a more descriptive
	 * error than we would get by just trying to look it up in the file
	 * table and failing.
	 */
	if (fd == AT_FDCWD)
		return -ECAPMODE;

	rcu_read_lock();

	file = fcheck(fd);
	if (file == NULL) {
		result = -EBADF;
		goto out;
	}
	capsicum_unwrap(file, &actual_rights);

	/* Make an anti-TOCTOU record. We record the identity of the file
	 * this fd points to in thread-local data, at the same time as
	 * we check its permissions. The fget() hook can then check that it's
	 * looking up the same file we checked permissions on, preventing
	 * an exploitable race condition.
	 */
	pending = capsicum_get_pending_syscall();
	if (IS_ERR(pending)) {
		result = PTR_ERR(pending);
		goto out;
	}
	BUG_ON(pending->next_free >= ARRAY_SIZE(pending->files));
	pending->fds[pending->next_free] = fd;
	pending->files[pending->next_free] = file;
	pending->next_free++;

	if ((actual_rights & required_rights) == required_rights)
		result = 0;
	else
		result = -ENOTCAPABLE;
out:
	rcu_read_unlock();
	return result;
}

int capsicum_is_cap(const struct file *file)
{
	return file->f_op == &capability_ops;
}

/*
 * Allocate a capability object. This is separate from initialisation, because
 * we pre-allocate capabilities for use in capsicum_file_install().
 */
struct file *capsicum_cap_alloc(void)
{
	struct capability *cap;
	struct file *newfile;

	cap = kmalloc(sizeof(*cap), GFP_KERNEL);
	if (cap == NULL)
		return ERR_PTR(-ENOMEM);

	newfile = anon_inode_getfile("[capability]", &capability_ops, cap, 0);
	if (IS_ERR(newfile))
		kfree(cap);

	return newfile;
}

/* Initialise an already-allocated capability to point to the given underlying
 * file with the given rights. capf must be a capability previously allocated
 * with capsicum_cap_alloc().
 */
void capsicum_cap_set(struct file *capf, struct file *underlying, u64 rights)
{
	struct capability *cap = capf->private_data;

	BUG_ON(!capsicum_is_cap(capf));
	BUG_ON(!cap);
	cap->underlying = underlying;
	cap->rights = rights;
}

int capsicum_wrap_new_fd(struct file *orig, u64 rights)
{
	int error, fd;
	struct file *file;

	error = get_unused_fd();
	if (error < 0)
		return error;
	fd = error;

	file = capsicum_cap_alloc();
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_put_unused_fd;
	}

	if (capsicum_is_cap(orig))
		orig = capsicum_unwrap(orig, NULL);
	get_file(orig);
	capsicum_cap_set(file, orig, rights);
	fd_install(fd, file);

	return fd;

err_put_unused_fd:
	put_unused_fd(fd);
	return error;
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

/*
 * We are looking up a file by its file descriptor. If it is a capability,
 * we unwrap it and return the underlying file, recording its rights in
 * thread-local storage so we know what rights to give any new fd that this
 * syscall installs.
 *
 * If we were in capability mode, we performed a rights check on entry to the
 * current syscall. This function checks that the file we are unwrapping is
 * the same as the one which was examined in capsicum_intercept_syscall().
 */
static struct file *capsicum_file_lookup(struct file *file, unsigned int fd)
{
	struct file *unwrapped;
	struct capsicum_pending_syscall *pending;
	int i;
	bool found_fd = false;

	pending = capsicum_get_pending_syscall();
	if (IS_ERR(pending)) {
		printk(KERN_ERR "Cannot allocate in capsicum_file_lookup()\n");
		return NULL;
	}

	/* Newly-installed file descriptors inherit the rights of the file
	 * descriptor used in the call that created them. So record the rights
	 * of the file we just looked up (full rights if it wasn't a
	 * capability).
	 */
	pending->new_cap_rights = (u64)-1;
	unwrapped = capsicum_unwrap(file, &pending->new_cap_rights);
	if (!unwrapped)
		return file;

	/* Verify that this file descriptor is the same one we checked when
	 * we were deciding whether to allow this syscall in the first place.
	 * This is only relevant in capability mode, because we don't check
	 * otherwise.
	 *
	 * Even if we've found a lookup record, we still check all the others,
	 * to prevent a race where the user could change the identity of a
	 * single fd passed as two parameters to the same call. If there are
	 * multiple records of the same fd in pending, we want to check them
	 * all.
	 */
	if (capsicum_current_cap_mode()) {
		for (i = 0; i < pending->next_free; i++) {
			if (pending->fds[i] == fd) {
				found_fd = true;
				if (pending->files[i] != file)
					return NULL;
			}
		}
		BUG_ON(!found_fd);
	}

	return unwrapped;
}

/* We are about to install @file in @fd. This hook allows us to change which
 * file actually gets stored in the process's file table. In particular, if the
 * last file to be looked up was a capability, we wrap the file we are about to
 * install in a capability with the same rights.
 *
 * Because fd_install() cannot return an error, we take this opportunity to
 * pre-allocate a capability and place it in thread-local storage, at a point
 * where it is OK to abort.
 */
static int capsicum_fd_alloc(unsigned int fd)
{
	struct file *capf;
	struct capsicum_pending_syscall *pending;

	/* Optimisation: If we haven't worked with capabilities so far in this
	 * thread, there is no need to allocate a structure just to say so.
	 */
	if (!current_security())
		return 0;

	pending = capsicum_get_pending_syscall();
	if (IS_ERR(pending))
		return PTR_ERR(pending);

	if (!pending->next_new_cap) {
		capf = capsicum_cap_alloc();
		if (IS_ERR(capf))
			return PTR_ERR(capf);
		pending->next_new_cap = capf;
	}
	return 0;
}

/* We are about to install @file in @fd. This hook allows us to change which
 * file actually gets stored in the process's file table. In particular, if the
 * last file to be looked up was a capability, we wrap the file we are about to
 * install in a capability with the same rights.
 */
static struct file *capsicum_file_install(struct file *file, unsigned int fd)
{
	struct capsicum_pending_syscall *pending;
	struct file *capf;

	pending = current_security();
	if (!pending)
		return file;

	BUG_ON(pending->task != current);

	if (pending->new_cap_rights == (u64)-1 || capsicum_is_cap(file))
		return file;

	/* We cannot signal failure from here, so we rely on a preallocated
	 * capability wrapper from capsicum_fd_alloc(). */
	BUG_ON(!pending->next_new_cap);

	capf = pending->next_new_cap;
	capsicum_cap_set(capf, file, pending->new_cap_rights);
	pending->next_new_cap = NULL;
	pending->new_cap_rights = 0;

	return capf;
}

/* In capability mode, we restrict processes' paths by denying absolute
 * path lookup, and allowing only downward lookups from file descriptors
 * using openat() and friends. We therefore prevent absolute lookups
 * and upward traversal (../) in capability mode.
 */
static int capsicum_path_lookup(struct dentry *dentry, const char *name)
{
	if (!capsicum_current_cap_mode())
		return 0;

	if (name[0] == '.' && name[1] == '.' &&
			(name[2] == '\0' || name[2] == '/'))
		return -ECAPMODE;

	if (name[0] == '/')
		return -ECAPMODE;

	return 0;
}

/* Return (and allocate if necessary) the thread-local storage we use to
 * record details of the current system call.
 */
struct capsicum_pending_syscall *capsicum_get_pending_syscall(void)
{
	struct capsicum_pending_syscall *pending = current_security();

	if (!pending || pending->task != current) {
		struct cred *cred;

		cred = prepare_creds();
		if (!cred)
			return ERR_PTR(-ENOMEM);

		/* If we're unsharing a cred which already points to some other
		 * thread's capsicum_pending_syscall, capsicum_cred_prepare()
		 * will dup that capsicum_pending_syscall into our new cred -
		 * so the memory we need might already be allocated.
		 */
		pending = cred->security;
		if (!pending) {
			pending = kmalloc(sizeof(*pending), GFP_KERNEL);
			if (!pending) {
				abort_creds(cred);
				return ERR_PTR(-ENOMEM);
			}
			cred->security = pending;
		}

		commit_creds(cred);
		pending->new_cap_rights = (u64)-1;
		pending->next_free = 0;
		pending->next_new_cap = NULL;
		pending->task = current;
	}

	return pending;
}

static void capsicum_cred_free(struct cred *cred)
{
	kfree(cred->security);
	cred->security = NULL;
}

static int capsicum_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	cred->security = kmalloc(sizeof(struct capsicum_pending_syscall), gfp);
	if (!cred->security)
		return -ENOMEM;
	return 0;
}

static void capsicum_cred_transfer(struct cred *new, const struct cred *old)
{
	BUG_ON(!new->security);
	memcpy(new->security, old->security,
			sizeof(struct capsicum_pending_syscall));
}

static int capsicum_cred_prepare(struct cred *new, const struct cred *old,
		gfp_t gfp)
{
	struct capsicum_pending_syscall *pending = old->security;

	if (pending && pending->task == current) {
		int err = capsicum_cred_alloc_blank(new, gfp);
		if (err)
			return err;
		capsicum_cred_transfer(new, old);
	}

	return 0;
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
	.setlease = panic_ptr
};

static struct security_operations capsicum_security_ops = {
		.name = "capsicum",
		.file_lookup = capsicum_file_lookup,
		.fd_alloc = capsicum_fd_alloc,
		.file_install = capsicum_file_install,
		.path_lookup = capsicum_path_lookup,
		.cred_alloc_blank = capsicum_cred_alloc_blank,
		.cred_free = capsicum_cred_free,
		.cred_prepare = capsicum_cred_prepare,
		.cred_transfer = capsicum_cred_transfer
};
