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

static int open_or_die(const char *filename, int flags)
{
	int fd = open(filename, flags);
	if (fd < 0) {
		printf("Failed to open '%s'; "
			"check prerequisites are available\n", filename);
		exit(1);
	}
}

static int run_tests(void)
{
	int fail = 0;
	char *fullname = realpath("execveat", NULL);
	char *fullname_script = realpath("script", NULL);
	char *fullname_symlink = concat(fullname, ".symlink");
	int subdir_dfd = open_or_die("subdir", O_DIRECTORY|O_RDONLY);
	int subdir_dfd_ephemeral = open_or_die("subdir.ephemeral",
					       O_DIRECTORY|O_RDONLY);
	int dot_dfd = open_or_die(".", O_DIRECTORY|O_RDONLY);
	int dot_dfd_path = open_or_die(".", O_DIRECTORY|O_RDONLY|O_PATH);
	int fd = open_or_die("execveat", O_RDONLY);
	int fd_path = open_or_die("execveat", O_RDONLY|O_PATH);
	int fd_symlink = open_or_die("execveat.symlink", O_RDONLY);
	int fd_script = open_or_die("script", O_RDONLY);
	int fd_ephemeral = open_or_die("execveat.ephemeral", O_RDONLY);
	int fd_script_ephemeral = open_or_die("script.ephemeral", O_RDONLY);

	/* Normal executable file: */
	/*   dfd + path */
	fail |= check_execveat(subdir_dfd, "../execveat", 0);
	fail |= check_execveat(dot_dfd, "execveat", 0);
	fail |= check_execveat(dot_dfd_path, "execveat", 0);
	/*   absolute path */
	fail |= check_execveat(AT_FDCWD, fullname, 0);
	/*   absolute path with nonsense dfd */
	fail |= check_execveat(99, fullname, 0);
	/*   fd + no path */
	fail |= check_execveat(fd, NULL, 0);

	/* Mess with executable file that's already open: */
	/*   fd + no path to a file that's been renamed */
	rename("execveat.ephemeral", "execveat.moved");
	fail |= check_execveat(fd_ephemeral, NULL, 0);
	/*   fd + no path to a file that's been deleted */
	unlink("execveat.moved"); /* remove the file now fd open */
	fail |= check_execveat(fd_ephemeral, NULL, 0);

	/* Symlink to executable file: */
	/*   dfd + path */
	fail |= check_execveat(dot_dfd, "execveat.symlink", 0);
	fail |= check_execveat(dot_dfd_path, "execveat.symlink", 0);
	/*   absolute path */
	fail |= check_execveat(AT_FDCWD, fullname_symlink, 0);
	/*   fd + no path, even with AT_SYMLINK_NOFOLLOW (already followed) */
	fail |= check_execveat(fd_symlink, NULL, 0);
	fail |= check_execveat(fd_symlink, NULL, AT_SYMLINK_NOFOLLOW);

	/* Symlink fails when AT_SYMLINK_NOFOLLOW set: */
	/*   dfd + path */
	fail |= check_execveat_fail(dot_dfd, "execveat.symlink",
				    AT_SYMLINK_NOFOLLOW, ELOOP);
	fail |= check_execveat_fail(dot_dfd_path, "execveat.symlink",
				    AT_SYMLINK_NOFOLLOW, ELOOP);
	/*   absolute path */
	fail |= check_execveat_fail(AT_FDCWD, fullname_symlink,
				    AT_SYMLINK_NOFOLLOW, ELOOP);

	/* Shell script wrapping executable file: */
	/*   dfd + path */
	fail |= check_execveat(subdir_dfd, "../script", 0);
	fail |= check_execveat(dot_dfd, "script", 0);
	fail |= check_execveat(dot_dfd_path, "script", 0);
	/*   absolute path */
	fail |= check_execveat(AT_FDCWD, fullname_script, 0);
	/*   fd + no path */
	fail |= check_execveat(fd_script, NULL, 0);
	fail |= check_execveat(fd_script, NULL, AT_SYMLINK_NOFOLLOW);

	/* Mess with script file that's already open: */
	/*   fd + no path to a file that's been renamed */
	rename("script.ephemeral", "script.moved");
	fail |= check_execveat(fd_script_ephemeral, NULL, 0);
	/*   fd + no path to a file that's been deleted */
	unlink("script.moved"); /* remove the file while fd open */
	/* Shell attempts to load the deleted file but fails => rc=127 */
	fail |= check_execveat_invoked_rc(fd_script_ephemeral, NULL, 0, 127);

	/* Rename a subdirectory in the path: */
	rename("subdir.ephemeral", "subdir.moved");
	fail |= check_execveat(subdir_dfd_ephemeral, "../script", 0);
	fail |= check_execveat(subdir_dfd_ephemeral, "script", 0);
	/* Remove the subdir and its contents */
	unlink("subdir.moved/script");
	unlink("subdir.moved");
	/* Shell loads via deleted subdir OK because name starts with .. */
	fail |= check_execveat(subdir_dfd_ephemeral, "../script", 0);
	fail |= check_execveat_fail(subdir_dfd_ephemeral, "script", 0, ENOENT);

	/* Flag values other than AT_SYMLINK_NOFOLLOW => EINVAL */
	fail |= check_execveat_fail(dot_dfd, "execveat", 0xFFFF, EINVAL);
	/* Invalid path => ENOENT */
	fail |= check_execveat_fail(dot_dfd, "no-such-file", 0, ENOENT);
	fail |= check_execveat_fail(dot_dfd_path, "no-such-file", 0, ENOENT);
	fail |= check_execveat_fail(AT_FDCWD, "no-such-file", 0, ENOENT);
	/* Attempt to execute directory => EACCES */
	fail |= check_execveat_fail(dot_dfd, NULL, 0, EACCES);
	/* Attempt to execute non-executable => EACCES */
	fail |= check_execveat_fail(dot_dfd, "Makefile", 0, EACCES);
	/* Attempt to execute file opened with O_PATH => EBADF */
	fail |= check_execveat_fail(dot_dfd_path, NULL, 0, EBADF);
	fail |= check_execveat_fail(fd_path, NULL, 0, EBADF);
	/* Attempt to execute nonsense FD => EBADF */
	fail |= check_execveat_fail(99, NULL, 0, EBADF);
	fail |= check_execveat_fail(99, "execveat", 0, EBADF);
	/* Attempt to execute relative to non-directory => ENOTDIR */
	fail |= check_execveat_fail(fd, "execveat", 0, ENOTDIR);

	return fail ? -1 : 0;
}

int main(int argc, char **argv)
{
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
	} else {
		return run_tests();
	}
}
