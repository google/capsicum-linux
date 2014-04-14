/*
 * Copyright (c) 2014 Google, Inc.
 *
 * Licensed under the terms of the GNU GPL License version 2
 *
 * Selftests for execveat(2).
 */

#define _GNU_SOURCE  /* to get O_PATH */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

static char *envp[] = { "IN_TEST=yes", NULL };
static char *argv[] = { "execveat", "99", NULL };

static int execveat_(int fd, const char *path, char **argv, char **envp,
		     int flags)
{
#ifdef __NR_execveat
	return syscall(__NR_execveat, fd, path, argv, envp, flags);
#else
	errno = -ENOSYS;
	return -1;
#endif
}

#define check_execveat_fail(fd, path, flags, errno)	\
	_check_execveat_fail(fd, path, flags, errno, #errno)
static int _check_execveat_fail(int fd, const char *path, int flags,
				int expected_errno, const char *errno_str)
{
	errno = 0;
	printf("Check failure of execveat(%d, '%s', %d) with %s... ",
		fd, path?:"(null)", flags, errno_str);
	int rc = execveat_(fd, path, argv, envp, flags);
	if (rc > 0) {
		printf("[FAIL] (unexpected success from execveat(2))\n");
		return 1;
	}
	if (errno != expected_errno) {
		printf("[FAIL] (expected errno %d (%s) not %d (%s)\n",
			expected_errno, strerror(expected_errno),
			errno, strerror(errno));
		return 1;
	}
	printf("[OK]\n");
	return 0;
}

static int check_execveat_invoked_rc(int fd, const char *path, int flags,
				     int expected_rc)
{
	int status;
	int rc;
	pid_t child;
	printf("Check success of execveat(%d, '%s', %d)... ",
		fd, path?:"(null)", flags);
	child = fork();
	if (child < 0) {
		printf("[FAIL] (fork() failed)\n");
		return 1;
	}
	if (child == 0) {
		/* Child: do execveat(). */
		rc = execveat_(fd, path, argv, envp, flags);
		printf("[FAIL]: execveat() failed, rc=%d errno=%d (%s)\n",
			rc, errno, strerror(errno));
		exit(1);  /* should not reach here */
	}
	/* Parent: wait for & check child's exit status. */
	rc = waitpid(child, &status, 0);
	if (rc != child) {
		printf("[FAIL] (waitpid(%d,...) returned %d)\n", child, rc);
		return 1;
	}
	if (!WIFEXITED(status)) {
		printf("[FAIL] (child %d did not exit cleanly, status=%08x)\n",
			child, status);
		return 1;
	}
	if (WEXITSTATUS(status) != expected_rc) {
		printf("[FAIL] (child %d exited with %d not %d)\n",
			child, WEXITSTATUS(status), expected_rc);
		return 1;
	}
	printf("[OK]\n");
	return 0;
}

static int check_execveat(int fd, const char *path, int flags)
{
	return check_execveat_invoked_rc(fd, path, flags, 99);
}

static char *concat(const char *left, const char *right)
{
	char *result = malloc(strlen(left) + strlen(right) + 1);
	strcpy(result, left);
	strcat(result, right);
}

int main(int argc, char **argv)
{
	int failed = 0;
	int fd;
	int dfd;
	int dot_dfd;
	int dot_dfd_path;
	int fd_path;
	int fd_symlink;
	int fd_sh;
	int fd_ephemeral;
	int fd_sh_ephemeral;
	char *name_dotdot;
	char *name_symlink;
	char *name_sh;
	char *name_ephemeral;
	char *name_moved;
	char *name_sh_ephemeral;
	char *name_sh_moved;
	char *name_sh_dotdot;
	char *fullname;
	char *fullname_symlink;
	char *fullname_sh;

	if (argc >= 2) {
		/* If we are invoked with an argument, exit immediately. */
		/* Check expected environment transferred. */
		if (strcmp(getenv("IN_TEST"), "yes") != 0) {
			printf("[FAIL] (no IN_TEST=yes in env)\n");
			return 1;
		}

		/* Use the argument as an exit code. */
		int rc = atoi(argv[1]);
		fflush(stdout);
		return rc;
	}

	dfd = open("subdir", O_DIRECTORY|O_RDONLY);
	dot_dfd = open(".", O_DIRECTORY|O_RDONLY);
	dot_dfd_path = open(".", O_DIRECTORY|O_RDONLY|O_PATH);
	fd = open(argv[0], O_RDONLY);
	fd_path = open(argv[0], O_RDONLY|O_PATH);

	name_dotdot = concat("../", argv[0]);
	name_symlink = concat(argv[0], ".symlink");
	name_sh = concat(argv[0], ".sh");
	name_ephemeral = concat(argv[0], ".ephemeral");
	name_moved = concat(argv[0], ".moved");
	name_sh_ephemeral = concat(name_sh, ".ephemeral");
	name_sh_moved = concat(name_sh, ".moved");
	name_sh_dotdot = concat("../", name_sh);
	fd_symlink = open(name_symlink, O_RDONLY);
	fd_sh = open(name_sh, O_RDONLY);
	fd_ephemeral = open(name_ephemeral, O_RDONLY);
	fd_sh_ephemeral = open(name_sh_ephemeral, O_RDONLY);
	fullname = realpath(argv[0], NULL);
	fullname_symlink = concat(fullname, ".symlink");
	fullname_sh = concat(fullname, ".sh");

	/* Normal executable file: */
	/*   dfd + path */
	failed |= check_execveat(dfd, name_dotdot, 0);
	failed |= check_execveat(dot_dfd, argv[0], 0);
	failed |= check_execveat(dot_dfd_path, argv[0], 0);
	/*   absolute path */
	failed |= check_execveat(AT_FDCWD, fullname, 0);
	/*   absolute path with nonsense dfd */
	failed |= check_execveat(99, fullname, 0);
	/*   fd + no path */
	failed |= check_execveat(fd, NULL, 0);

	/* Mess with file that's already open */
	/*   fd + no path to a file that's been renamed */
	rename(name_ephemeral, name_moved);
	failed |= check_execveat(fd_ephemeral, NULL, 0);
	/*   fd + no path to a file that's been deleted */
	unlink(name_moved); /* remove the file now fd open */
	failed |= check_execveat(fd_ephemeral, NULL, 0);

	/* Symlink to executable file: */
	/*   dfd + path */
	failed |= check_execveat(dot_dfd, name_symlink, 0);
	failed |= check_execveat(dot_dfd_path, name_symlink, 0);
	/*   absolute path */
	failed |= check_execveat(AT_FDCWD, fullname_symlink, 0);
	/*   fd + no path, even with AT_SYMLINK_NOFOLLOW (already followed) */
	failed |= check_execveat(fd_symlink, NULL, 0);
	failed |= check_execveat(fd_symlink, NULL, AT_SYMLINK_NOFOLLOW);

	/* Symlink fails when AT_SYMLINK_NOFOLLOW set: */
	/*   dfd + path */
	failed |= check_execveat_fail(dot_dfd, name_symlink,
				      AT_SYMLINK_NOFOLLOW, ELOOP);
	failed |= check_execveat_fail(dot_dfd_path, name_symlink,
				      AT_SYMLINK_NOFOLLOW, ELOOP);
	/*   absolute path */
	failed |= check_execveat_fail(AT_FDCWD, fullname_symlink,
				      AT_SYMLINK_NOFOLLOW, ELOOP);

	/* Shell script wrapping executable file: */
	/*   dfd + path */
	failed |= check_execveat(dfd, name_sh_dotdot, 0);
	failed |= check_execveat(dot_dfd, name_sh, 0);
	failed |= check_execveat(dot_dfd_path, name_sh, 0);
	/*   absolute path */
	failed |= check_execveat(AT_FDCWD, fullname_sh, 0);
	/*   fd + no path */
	failed |= check_execveat(fd_sh, NULL, 0);
	failed |= check_execveat(fd_sh, NULL, AT_SYMLINK_NOFOLLOW);

	/* Mess with script file that's already open */
	rename(name_sh_ephemeral, name_sh_moved);
	failed |= check_execveat(fd_sh_ephemeral, NULL, 0);
	/*   fd + no path to a file that's been deleted */
	unlink(name_sh_moved); /* remove the file now fd open */
	/* Shell attempts to load the deleted file but fails => rc=127 */
	failed |= check_execveat_invoked_rc(fd_sh_ephemeral, NULL, 0, 127);

	/* Flag values other than AT_SYMLINK_NOFOLLOW => EINVAL */
	failed |= check_execveat_fail(dot_dfd, argv[0], 0xFFFF, EINVAL);
	/* Invalid path => ENOENT */
	failed |= check_execveat_fail(dot_dfd, "no-such-file", 0, ENOENT);
	failed |= check_execveat_fail(dot_dfd_path, "no-such-file", 0, ENOENT);
	failed |= check_execveat_fail(AT_FDCWD, "no-such-file", 0, ENOENT);
	/* Attempt to execute directory => EACCES */
	failed |= check_execveat_fail(dot_dfd, NULL, 0, EACCES);
	/* Attempt to execute non-executable => EACCES */
	failed |= check_execveat_fail(dot_dfd, "Makefile", 0, EACCES);
	/* Attempt to execute file opened with O_PATH => EBADF */
	failed |= check_execveat_fail(dot_dfd_path, NULL, 0, EBADF);
	failed |= check_execveat_fail(fd_path, NULL, 0, EBADF);
	/* Attempt to execute nonsense FD => EBADF */
	failed |= check_execveat_fail(99, NULL, 0, EBADF);
	failed |= check_execveat_fail(99, argv[0], 0, EBADF);
	/* Attempt to execute relative to non-directory => ENOTDIR */
	failed |= check_execveat_fail(fd, argv[0], 0, ENOTDIR);

	return failed ? -1 : 0;
}
