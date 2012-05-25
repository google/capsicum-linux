/* 
 * Tests for the process descriptor API for Linux.
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

static inline int pdfork(int *fd, int flags)
{
	return syscall(313, fd, flags);
}

static inline int pdgetpid(int fd, pid_t *pidp)
{
	return syscall(314, fd, pidp);
}

static inline int pdkill(int fd, int signum)
{
	return syscall(315, fd, signum);
}

static inline int pdwait4(int fd, int *status, int options, struct rusage *rusage)
{
	return syscall(316, fd, status, options, rusage);
}

#endif /*__CAPSICUM_USERSPACE_H__*/

