/*
 * Kernel-space unit tests for Capsicum, a capability API for UNIX.
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
#include <linux/audit.h>
#include <linux/printk.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#include "capsicum_int.h"

#include <misc/test_harness.h>

/*
 * These unit tests exercise the Capsicum security module.
 */


/* Test the wrapping and unwrapping of file descriptors in capabilities. */
FIXTURE(new_cap) {
	struct file *orig;
	int cap;
	struct file *capf;
};

FIXTURE_SETUP(new_cap) {
	self->orig = fget(0);
	ASSERT_NE(self->orig, NULL);
	self->cap = capsicum_wrap_new_fd(self->orig, 0);
	ASSERT_GE(self->cap, 0);
	/* The new capability fd must not be the same as the original (0). */
	ASSERT_NE(self->cap, 0);
	self->capf = fcheck(self->cap);
	ASSERT_NE(self->capf, NULL);
}

FIXTURE_TEARDOWN(new_cap) {
	fput(self->orig);
	sys_close(self->cap);
}

TEST_F(new_cap, init_ok) {
	u64 rights;
	struct file *f;

	EXPECT_GT(file_count(self->orig), 1);
	EXPECT_EQ(file_count(self->capf), 1);

	rights = (u64)-1;
	f = capsicum_unwrap(self->capf, &rights);
	/* Verify that the rights are as we set them in setup. */
	EXPECT_EQ(rights, 0);
	EXPECT_EQ(f, self->orig);
}

TEST_F(new_cap, rewrap) {
	/* When we wrap an fd in a capability, then wrap that second fd
	 * in another capability, the new capability will refer to the same
	 * original file, and the reference count of the original file
	 * will be incremented.
	 */
	struct file *f, *unwrapped_file;
	u64 rights;

	int old_count, fd;

	old_count = file_count(self->orig);

	fd = capsicum_wrap_new_fd(self->capf, -1);
	ASSERT_GT(fd, 0);
	f = fcheck(fd);

	unwrapped_file = capsicum_unwrap(f, &rights);
	EXPECT_EQ(rights, -1);
	EXPECT_EQ(unwrapped_file, self->orig);

	EXPECT_EQ(file_count(self->orig), old_count + 1);

	sys_close(fd);

	EXPECT_EQ(file_count(self->orig), old_count);
}

TEST_F(new_cap, is_cap) {
	EXPECT_TRUE(capsicum_is_cap(self->capf));
	EXPECT_FALSE(capsicum_is_cap(self->orig));
}


/* Test that the fget() family of functions unwraps capabilities correctly. */
FIXTURE(fget) {
	struct file *orig;
	int cap;

	int orig_refs;
};

FIXTURE_SETUP(fget) {
	self->orig = fget(0);
	self->orig_refs = file_count(self->orig);
	self->cap = capsicum_wrap_new_fd(self->orig, 0);
	ASSERT_EQ(file_count(self->orig), self->orig_refs+1);
	ASSERT_EQ(file_count(fcheck(self->cap)), 1);
}

FIXTURE_TEARDOWN(fget) {
	ASSERT_EQ(file_count(self->orig), self->orig_refs+1);
	sys_close(self->cap);
	ASSERT_EQ(file_count(self->orig), self->orig_refs);
	fput(self->orig);
	ASSERT_EQ(file_count(self->orig), self->orig_refs-1);
}

TEST_F(fget, fget) {
	struct file *f = fget(self->cap);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_light) {
	int fpn;
	struct file *f = fget_light(self->cap, &fpn);

	EXPECT_EQ(f, self->orig);
	EXPECT_FALSE(fpn);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
}

TEST_F(fget, fget_raw) {
	struct file *f = fget_raw(self->cap);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_raw_light) {
	int fpn;
	struct file *f = fget_raw_light(self->cap, &fpn);


	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(fpn, 0);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
}

/* Simulate a TOCTOU (time-of-check/time-of-use) attack, and verify that it
 * is prevented. */
TEST_F(fget, simulate_toctou) {
	int fd_with_rights;
	int result;
	char dest = '\0';
	unsigned long write_args[3];
	struct file *retrieved;

	/* This test requires capability mode, but we can't leave our test
	 * process (/sbin/init) in cap mode, so we need to un-set capability
	 * mode before the test completes. As there is (by design) no API for
	 * doing this, we reach in and flip the thread flags manually.
	 */
	set_thread_flag(TIF_SECCOMP);
	current->seccomp.mode = SECCOMP_MODE_CAPSICUM;

	/* Let's pretend we're executing a syscall. We have one
	 * capability with rights, and one without (self->cap).
	 */
	fd_with_rights = capsicum_wrap_new_fd(self->orig, CAP_WRITE|CAP_SEEK);

	/* The process starts to execute a syscall, on our fd with rights. */
	write_args[0] = fd_with_rights;
	write_args[1] = (unsigned long)&dest;
	write_args[2] = 1;

	result = capsicum_intercept_syscall(AUDIT_ARCH_X86_64, __NR_write,
			write_args);
	EXPECT_EQ(result, 0);

	/* But before sys_write() retrieves the file, the dastardly process
	 * changes the fd to point to something entirely different, to which
	 * we should have no rights at all.
	 */
	sys_dup2(self->cap, fd_with_rights);

	/* sys_write() now tries to retrieve that file. */
	retrieved = fget(fd_with_rights);

	/* It should detect the change and return nothing. (Logically, we
	 * just "fell down the cracks" between the unmapping of the old
	 * fd and the mapping of the new one. If it got anything back, we lose.
	 */
	EXPECT_EQ(retrieved, NULL);

	/* Avoid ref-count errors when the test fails. */
	if (retrieved)
		fput(retrieved);

	sys_close(fd_with_rights);

	/* Flip the flag to get us out of cap mode (no API for this). */
	clear_thread_flag(TIF_SECCOMP);
}

/* Preparing a new cred duplicates our thread-local state structure. */
TEST(cred_copy_pending) {
	const struct cred *old_cred;
	struct cred *new_cred;
	struct capsicum_pending_syscall *pending;

	pending = capsicum_get_pending_syscall();
	old_cred = current_cred();
	EXPECT_EQ(old_cred->security, pending);

	new_cred = prepare_creds();
	EXPECT_NE(new_cred->security, NULL);
	EXPECT_NE(new_cred->security, old_cred->security);
	EXPECT_TRUE(!memcmp(new_cred->security, old_cred->security,
			sizeof(struct capsicum_pending_syscall)));

	commit_creds(new_cred);
	EXPECT_EQ(current_cred(), new_cred);
}

/* If the thread-local Capsicum state object attached to our cred does not
 * belong to our thread (ie the cred is shared), capsicum_get_pending_syscall()
 * will allocate us our own private cred and thread-local object.
 */
TEST(unshare_cred) {
	const struct cred *old_cred;
	struct capsicum_pending_syscall *old_pending, *new_pending;

	old_pending = capsicum_get_pending_syscall();
	old_cred = current_cred();
	ASSERT_EQ(old_cred->security, old_pending);

	/* Spike this object, so that it looks foreign to
	 * capsicum_get_pending_syscall(), which will allocate a new
	 * state object and a new cred to hold it.
	 */
	old_pending->task = NULL;

	new_pending = capsicum_get_pending_syscall();
	EXPECT_NE(new_pending, old_pending);
	EXPECT_NE(current_cred(), old_cred);
}

/* Custom syscall parsing */
FIXTURE(customcall) {
	unsigned long args[6];
};

FIXTURE_SETUP(customcall) {
	int i;

	for (i = 0; i < 6; i++)
		self->args[i] = 0;
}

FIXTURE_TEARDOWN(customcall) {}

/* capability checks are enforced on file-based mmap() calls, but not anonymous
 * ones.
 */
static int run_table(int call, unsigned long *args)
{
	return capsicum_run_syscall_table(AUDIT_ARCH_X86_64, call, args);
}

TEST_F(customcall, mmap) {
	int cap_none, cap_mmap, cap_read, cap_both;
	unsigned long *afd = &(self->args[4]);
	struct file *file;

	self->args[2] = PROT_READ;
	file = fget(0);
	ASSERT_NE(file, NULL);

	/* If we're missing a capability, it will fail. */
	cap_none = capsicum_wrap_new_fd(file, CAP_NONE);
	cap_mmap = capsicum_wrap_new_fd(file, CAP_MMAP);
	cap_read = capsicum_wrap_new_fd(file, CAP_READ);
	cap_both = capsicum_wrap_new_fd(file, CAP_MMAP | CAP_READ);

	fput(file);

	*afd = cap_none;
	EXPECT_EQ(-ENOTCAPABLE, run_table(__NR_mmap, self->args));

	*afd = cap_mmap;
	EXPECT_EQ(-ENOTCAPABLE, run_table(__NR_mmap, self->args));

	*afd = cap_read;
	EXPECT_EQ(-ENOTCAPABLE, run_table(__NR_mmap, self->args));

	*afd = cap_both;
	EXPECT_EQ(0, run_table(__NR_mmap, self->args));

	/* But a call with MAP_ANONYMOUS should succeed without any capability
	 * requirements.
	 */
	self->args[3] = MAP_ANONYMOUS;
	*afd = (unsigned long)-1;
	EXPECT_EQ(0, run_table(__NR_mmap, self->args));
}

TEST_HARNESS_DEBUGFS_TRIGGER(capsicum)
