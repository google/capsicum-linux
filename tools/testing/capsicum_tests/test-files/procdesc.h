/* 
 * Tests for the process descriptor API for Linux.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef __PROCDESC_USERSPACE_H__
#define __PROCDESC_USERSPACE_H__

#include <stdint.h>
#include <linux/procdesc.h>

static inline int pdfork(int *fd, int flags)
{
	return syscall(315, fd, flags);
}

static inline int pdgetpid(int fd, pid_t *pidp)
{
	return syscall(316, fd, pidp);
}

static inline int pdkill(int fd, int signum)
{
	return syscall(317, fd, signum);
}

static inline int pdwait4(int fd, int *status, int options, struct rusage *rusage)
{
	return syscall(318, fd, status, options, rusage);
}

#endif /*__PROCDESC_USERSPACE_H__*/

