/*
 * Part of a Linux implementation of Capsicum, a capability API for UNIX.
 * kt opens a debugfs file, and makes a single system call to write to it.
 * This is necessary because some of our tests play with fork(), so it is
 * imperative that we *not* do anything after write() returns, and that we
 * ignore its return value.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef DEBUGFS_MOUNT
#define DEBUGFS_MOUNT "/sys/kernel/debug"
#endif

int main(int argc, char **argv)
{
	char filename[512] = DEBUGFS_MOUNT "/run_capsicum_tests";
	char *test = "";
	int fd;

	if (argc >= 3)
		test = argv[2];

	if (argc >= 2)
		snprintf(filename, sizeof(filename),
			 DEBUGFS_MOUNT "/run_%s_tests", argv[1]);

	fd = open(filename, O_WRONLY);
	if (fd < 0) {
		perror(filename);
		return 1;
	}

	write(fd, test, strlen(test));

	return 0;
}

