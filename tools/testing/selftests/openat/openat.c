#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <linux/fcntl.h>

/* Bypass glibc */
static int openat_(int dirfd, const char *pathname, int flags)
{
	return syscall(__NR_openat, dirfd, pathname, flags);
}

static int openat_or_die(int dfd, const char *path, int flags)
{
	int fd = openat_(dfd, path, flags);
	if (fd < 0) {
		printf("Failed to openat(%d, '%s'); "
			"check prerequisites are available\n", dfd, path);
		exit(1);
	}
}

static int check_openat(int dfd, const char *path, int flags)
{
	int rc;
	int fd;
	char buffer[4];

	errno = 0;
	printf("Check success of openat(%d, '%s', %x)... ",
	       dfd, path?:"(null)", flags);
	fd = openat_(dfd, path, flags);
	if (fd < 0) {
		printf("[FAIL]: openat() failed, rc=%d errno=%d (%s)\n",
			fd, errno, strerror(errno));
		return 1;
	}
	errno = 0;
	rc = read(fd, buffer, sizeof(buffer));
	if (rc < 0) {
		printf("[FAIL]: read() failed, rc=%d errno=%d (%s)\n",
			rc, errno, strerror(errno));
		return 1;
	}
	close(fd);
	printf("[OK]\n");
	return 0;
}

#define check_openat_fail(dfd, path, flags, errno)	\
	_check_openat_fail(dfd, path, flags, errno, #errno)
static int _check_openat_fail(int dfd, const char *path, int flags,
			      int expected_errno, const char *errno_str)
{
	errno = 0;
	printf("Check failure of openat(%d, '%s', %x) with %s... ",
		dfd, path?:"(null)", flags, errno_str);
	int rc = openat_(dfd, path, flags);
	if (rc > 0) {
		printf("[FAIL] (unexpected success from openat(2))\n");
		close(rc);
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

int main(int argc, char *argv[])
{
	int fail = 0;
	int dot_dfd = openat_or_die(AT_FDCWD, ".", O_RDONLY);
	int subdir_dfd = openat_or_die(AT_FDCWD, "subdir", O_RDONLY);
	int file_fd = openat_or_die(AT_FDCWD, "topfile", O_RDONLY);

	/* Sanity check normal behavior */
	fail |= check_openat(AT_FDCWD, "topfile", O_RDONLY);
	fail |= check_openat(AT_FDCWD, "subdir/bottomfile", O_RDONLY);

	fail |= check_openat(dot_dfd, "topfile", O_RDONLY);
	fail |= check_openat(dot_dfd, "subdir/bottomfile", O_RDONLY);
	fail |= check_openat(dot_dfd, "subdir/../topfile", O_RDONLY);

	fail |= check_openat(subdir_dfd, "../topfile", O_RDONLY);
	fail |= check_openat(subdir_dfd, "bottomfile", O_RDONLY);
	fail |= check_openat(subdir_dfd, "../subdir/bottomfile", O_RDONLY);
	fail |= check_openat(subdir_dfd, "symlinkup", O_RDONLY);
	fail |= check_openat(subdir_dfd, "symlinkout", O_RDONLY);

	fail |= check_openat(AT_FDCWD, "/etc/passwd", O_RDONLY);
	fail |= check_openat(dot_dfd, "/etc/passwd", O_RDONLY);
	fail |= check_openat(subdir_dfd, "/etc/passwd", O_RDONLY);

	fail |= check_openat_fail(AT_FDCWD, "bogus", O_RDONLY, ENOENT);
	fail |= check_openat_fail(dot_dfd, "bogus", O_RDONLY, ENOENT);
	fail |= check_openat_fail(999, "bogus", O_RDONLY, EBADF);
	fail |= check_openat_fail(file_fd, "bogus", O_RDONLY, ENOTDIR);

#ifdef O_BENEATH_ONLY
	/* Test out O_BENEATH_ONLY */
	fail |= check_openat(AT_FDCWD, "topfile", O_RDONLY|O_BENEATH_ONLY);
	fail |= check_openat(AT_FDCWD, "subdir/bottomfile",
			     O_RDONLY|O_BENEATH_ONLY);

	fail |= check_openat(dot_dfd, "topfile", O_RDONLY|O_BENEATH_ONLY);
	fail |= check_openat(dot_dfd, "subdir/bottomfile",
			     O_RDONLY|O_BENEATH_ONLY);
	fail |= check_openat(subdir_dfd, "bottomfile", O_RDONLY|O_BENEATH_ONLY);

	/* Can't open paths with ".." in them */
	fail |= check_openat_fail(dot_dfd, "subdir/../topfile",
				O_RDONLY|O_BENEATH_ONLY, EACCES);
	fail |= check_openat_fail(subdir_dfd, "../topfile",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
	fail |= check_openat_fail(subdir_dfd, "../subdir/bottomfile",
				O_RDONLY|O_BENEATH_ONLY, EACCES);

	/* Can't open paths starting with "/" */
	fail |= check_openat_fail(AT_FDCWD, "/etc/passwd",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
	fail |= check_openat_fail(dot_dfd, "/etc/passwd",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
	fail |= check_openat_fail(subdir_dfd, "/etc/passwd",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
	/* Can't sneak around constraints with symlinks */
	fail |= check_openat_fail(subdir_dfd, "symlinkup",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
	fail |= check_openat_fail(subdir_dfd, "symlinkout",
				  O_RDONLY|O_BENEATH_ONLY, EACCES);
#else
	printf("Skipping O_BENEATH_ONLY tests due to missing #define\n");
#endif

	return fail ? -1 : 0;
}
