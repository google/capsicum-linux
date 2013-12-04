/*
 * Linux implementation of Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012-2013 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
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
 *  - A "process descriptor" mechanism which allows processes to
 *    refer to each other with file descriptors, which can then be
 *    capability-wrapped, allowing us to restrict access to the global PID
 *    namespace.
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
 * Per-thread Capsicum local state. This is used for two purposes:
 * - To check that file mappings haven't changed between the entry to a
 *   syscall, and the point that the LSM hooks are called to manipulate
 *   file descriptors. This prevents time-of-check/time-of-use (TOCTOU)
 *   races.
 * - When openat() on a capability is called, we pre-allocate a capability
 *   in case it needs wrapping at installation time, and store that capability
 *   in next_new_cap in the meanwhile (and store its rights in new_cap_rights).
 * Stored in current->cred->security.
 */
/* TODO(drysdale): remove this structure and re-write openat to be
 * capability-aware; involves removing all references to pending; also remove file_ */
struct capsicum_pending_syscall {
	/* Pre-allocated capability and associated rights */
	struct file *next_new_cap;
	cap_rights_t new_cap_rights;
	/*
	 * The back-reference to the task-struct allows us to detect when
	 * the cred struct gets shared between tasks, and un-share it.
	 */
	struct task_struct *task;
};

/*
 * Capability structure, holding the associated rights and underlying real file.
 * Capabilities are not stacked, i.e. underlying always points to a normal file
 * not another capability. Stored in file->private_data.
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
			current->seccomp.mode == SECCOMP_MODE_CAPSICUM;
}

static inline int capsicum_is_cap(const struct file *file)
{
	return file->f_op == &capsicum_file_ops;
}

/*
 * Allocate the thread-local storage we use to record details of the current
 * system call.  If there is already per-thread storage available, re-use that.
 */
static struct capsicum_pending_syscall *capsicum_alloc_pending_syscall(void)
{
	struct capsicum_pending_syscall *pending = current_security();

	if (!pending || pending->task != current) {
		/*
		 * Either there is no security data in the per-task credentials,
		 * or it is for a different thread.  Replace the per-task
		 * credentials with a new version that does include the security
		 * data for this thread.
		 */
		struct cred *cred;

		cred = prepare_creds();
		if (!cred)
			return ERR_PTR(-ENOMEM);

		/*
		 * If we're unsharing a cred which already points to some other
		 * thread's capsicum_pending_syscall, capsicum_cred_prepare()
		 * will have duplicated that capsicum_pending_syscall into our
		 * new cred - so the memory we need might already be allocated.
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

		pending->new_cap_rights = CAP_ALL;
		pending->next_new_cap = NULL;
		pending->task = current;
		commit_creds(cred);
	}

	return pending;
}

/*
 * Return the thread-local storage we use to record details of the current
 * system call, if it is present and is associated with the current thread.
 */
static struct capsicum_pending_syscall *capsicum_get_pending_syscall(void)
{
	struct capsicum_pending_syscall *pending = current_security();
	return (pending && pending->task == current) ? pending : NULL;
}

/*
 * Allocate a capability object. This is separate from initialisation, because
 * we pre-allocate capabilities for use in capsicum_file_install().
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
 * Initialise an already-allocated capability object. to point to the given
 * underlying file with the given rights.
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
 * Given a capability object, return the underlying file wrapped by that capability.
 * If rights is non-NULL, the capability's rights will be stored there too.
 * If cap is not a capability, returns NULL.
 */
static struct file *capsicum_unwrap(const struct file *capf,
				cap_rights_t *rights)
{
	struct capsicum_capability *cap;

	if (!capsicum_is_cap(capf))
		return NULL;

	cap = capf->private_data;

	if (rights)
		*rights = cap->rights;

	return cap->underlying;
}

/*
 * Wrap a file in a new capability object and install the capability object into
 * the file descriptor table.
 */
static int capsicum_install_fd(struct file *orig, cap_rights_t rights)
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

/* Include the per-syscall processing code */
#include "capsicum_syscall_table.h"

/*
 * Entrypoint to process an incoming syscall (from kernel/seccomp.c).
 * Returns 0 if the syscall should proceed, < 0 otherwise.
 */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args)
{
	int result;
	cap_rights_t existing_rights;

	if (!capsicum_enabled)
		return 0;

	result = capsicum_run_syscall_table(arch, callnr, args);

	existing_rights = CAP_ALL;
	if (result == 0 && callnr == __NR_openat) {
		struct file *file;
		rcu_read_lock();
		file = fcheck(args[0]);
		if (!file) {
			rcu_read_unlock();
			return -EBADF;
		}
		if (capsicum_unwrap(file, &existing_rights)) {
			/*
			 * We are performing openat(capfd,...) on a
			 * capability. This is the only way (other than
			 * cap_new(2)) of creating a new capability;
			 * pre-allocate a capability in this case so that when
			 * we come to install the new file descriptor, we can
			 * substitute in this capability wrapper (in
			 * capsicum_file_install).
			 */
			struct capsicum_pending_syscall *pending;
			pending = capsicum_alloc_pending_syscall();
			if (IS_ERR(pending)) {
				rcu_read_unlock();
				return PTR_ERR(pending);
			}
			pending->new_cap_rights = 0;

			if (!pending->next_new_cap) {
				pending->next_new_cap = capsicum_cap_alloc();
				if (IS_ERR(pending->next_new_cap)) {
					rcu_read_unlock();
					return PTR_ERR(pending->next_new_cap);
				}
			}
			/*
			 * Can theoretically find an existing pre-allocated
			 * capability hanging off the capsicum_pending_syscall
			 * if an earlier call to openat(capfd,...) for this
			 * thread failed later in the syscall processing (before
			 * the fd got installed). Re-use the capability, but
			 * update the rights.
			 */
			pending->new_cap_rights = existing_rights;
		}
		rcu_read_unlock();
	}

	return result;
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

	if (!capsicum_is_cap(file)) {
		result = -EINVAL;
		goto out_err;
	}
	capsicum_unwrap(file, &rights);
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
 * When we release a capability, release our reference to the underlying
 * (wrapped) file as well.
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
 * We are looking up a file by its file descriptor. If it is a capability,
 * and has the required rights, we unwrap it and return the underlying file.
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

	/* See if the file in question is a capability. */
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

/*
 * We are about to install @file in @fd. This hook allows us to change which
 * file actually gets stored in the process's file table. In particular, if the
 * last file to be looked up was a capability, we wrap the file we are about to
 * install in a capability with the same rights.
 */
/* TODO(drysdale): remove this (and the hook) when openat(2) is made cap-aware */
static struct file *capsicum_file_install(struct file *file, unsigned int fd)
{
	struct capsicum_pending_syscall *pending;
	struct file *capf;

	if (capsicum_is_cap(file))
		return file;

	pending = capsicum_get_pending_syscall();
	if (!pending)
		return file;

	if (pending->new_cap_rights == CAP_ALL || !pending->next_new_cap)
		return file;

	/* We are in the middle of processing a system call that allocates a few
	 * file descriptor for a capability, and the system call interception
	 * process has pre-allocated a capability wrapper for us.  Use it. */
	capf = pending->next_new_cap;
	capsicum_cap_set(capf, file, pending->new_cap_rights);
	pending->next_new_cap = NULL;
	pending->new_cap_rights = 0;

	return capf;
}

/*
 * In capability mode, we restrict processes' paths by denying absolute path
 * lookup, and allowing only downward lookups from file descriptors using
 * openat() and friends. We therefore prevent absolute lookups and upward
 * traversal (../) in capability mode.
 */
static int capsicum_path_lookup(struct dentry *dentry, const char *name)
{
	if (!capsicum_in_cap_mode())
		return 0;

	if (name[0] == '.' && name[1] == '.' &&
			(name[2] == '\0' || name[2] == '/'))
		return -ECAPMODE;

	if (name[0] == '/')
		return -ECAPMODE;

	return 0;
}

static void capsicum_cred_free(struct cred *cred)
{
	struct capsicum_pending_syscall *pending = cred->security;
	cred->security = NULL;
	if (pending) {
		if (pending->next_new_cap) {
			/* We're freeing a thread-local storage structure that
			 * has a pre-allocated capability hanging off it, so
			 * free that too. */
			put_filp(pending->next_new_cap);
		}
		kfree(pending);
	}
}

static int capsicum_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct capsicum_pending_syscall *pending;
	pending = kzalloc(sizeof(struct capsicum_pending_syscall), gfp);
	if (!pending)
		return -ENOMEM;
	pending->task = current;
	cred->security = pending;
	return 0;
}

static int capsicum_cred_prepare(struct cred *new, const struct cred *old,
		gfp_t gfp)
{
	const struct capsicum_pending_syscall *old_pending = old->security;

	/*
	 * Only bother setting up Capsicum cred structure if the old creds had
	 * one for this task.  This prevents non-Capsicum processes getting the
	 * overhead of Capsicum.
	 */
	if (old_pending && old_pending->task == current) {
		int ret = capsicum_cred_alloc_blank(new, gfp);
		if (ret)
			return ret;
	}

	return 0;
}

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
	.file_lookup = capsicum_file_lookup,
	.file_install = capsicum_file_install,
	.path_lookup = capsicum_path_lookup,
	.cred_alloc_blank = capsicum_cred_alloc_blank,
	.cred_free = capsicum_cred_free,
	.cred_prepare = capsicum_cred_prepare,
};

#include "capsicum_test.c"
