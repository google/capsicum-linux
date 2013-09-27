/* 
 * Tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef __CAPSICUM_USERSPACE_H__
#define __CAPSICUM_USERSPACE_H__

#include <stdint.h>
#include <sys/prctl.h>
#include <uapi/asm-generic/errno.h>
#include <misc/test_harness.h>
#include <../security/capsicum_caps.h>
#include <unistd.h>

static inline int cap_enter(void)
{
	return prctl(PR_SET_SECCOMP, 3);
}

static inline int cap_new(unsigned int fd, uint64_t rights)
{
	return syscall(314, fd, rights);
}

#endif /*__CAPSICUM_USERSPACE_H__*/

