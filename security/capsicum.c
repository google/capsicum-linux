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
 * so we include it here.
 */
#include "capsicum_syscall_table.h"

struct capability {
	u64 rights;
	struct file *underlying;
};

int enabled;

extern const struct file_operations capability_ops;
static struct security_operations capsicum_security_ops;

static int __init capsicum_init(void)
{
	enabled = security_module_enable(&capsicum_security_ops);
	if (enabled) {
		pr_debug("Capsicum enabled\n");
		register_security(&capsicum_security_ops);
	}

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
	return sys_cap_new_impl(orig_fd, new_rights);
}

int capsicum_intercept_syscall(void *syscall_entry, unsigned long *args)
{
	int result;
	struct capsicum_pending_syscalls *pending;

	pending = current_security();
	if (!pending) {
		struct cred *cred = prepare_creds();
		if (!cred)
			return -ENOMEM;
		cred->security = kmalloc(sizeof(*pending), GFP_KERNEL);
		pending = cred->security;
		commit_creds(cred);
	}

	pending->next_free = 0;

	result = run_syscall_table(syscall_entry, args);

	/* TODO(meredydd) custom syscalls here */

	return result;
}

static int require_rights(unsigned long fd, u64 required_rights)
{
	struct file *file;
	u64 actual_rights = (u64)-1;
	int result = -1;
	struct capsicum_pending_syscalls *pending;

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
	pending = current_security();
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
	struct file *unwrapped;
	struct capsicum_pending_syscalls *pending;
	int i;

	unwrapped = capsicum_unwrap(file, NULL);
	if (unwrapped == NULL)
		return file;

	/* If we're not in capability mode, don't enforce rights. */
	if (!capsicum_current_cap_mode())
		return unwrapped;

	pending = current_security();
	BUG_ON(!pending);

	for (i = 0; i < pending->next_free; i++) {
		if (pending->fds[i] == fd &&
				pending->files[i] != file) {
			return NULL;
		}
	}

	return unwrapped;
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

static void capsicum_task_free(struct task_struct *task)
{
	kfree(current_security());
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
		.file_lookup = capsicum_file_lookup,
		.path_lookup = capsicum_path_lookup,
		.task_free = capsicum_task_free
};
