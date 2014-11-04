#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/fcntl.h>

#ifndef ENOTBENEATH
#define ENOTBENEATH 134
#endif

/* Bypass glibc */
static int openat_(int dirfd, const char *pathname, int flags)
{
	return syscall(__NR_openat, dirfd, pathname, flags);
}
static int open_(const char *pathname, int flags, int mode)
{
	return syscall(__NR_open, pathname, flags, mode);
}
static int fcntl_(int fd, int cmd, int arg)
{
	return syscall(__NR_fcntl, fd, cmd, arg);
}

static int openat_or_die(int dfd, const char *path, int flags)
{
	int fd = openat_(dfd, path, flags);

	if (fd < 0) {
		printf("Failed to openat(%d, '%s'); "
			"check prerequisites are available\n", dfd, path);
		exit(1);
	}
	return fd;
}

static int check_fd(int fd)
{
	int rc;
	struct stat info;
	char buffer[4];

	if (fd < 0) {
		printf("[FAIL]: openat() failed, rc=%d errno=%d (%s)\n",
			fd, errno, strerror(errno));
		return 1;
	}
	if (fstat(fd, &info) != 0) {
		printf("[FAIL]: fstat() failed, rc=%d errno=%d (%s)\n",
			fd, errno, strerror(errno));
		return 1;
	}
	if (!S_ISDIR(info.st_mode)) {
		errno = 0;
		rc = read(fd, buffer, sizeof(buffer));
		if (rc < 0) {
			printf("[FAIL]: read() failed, rc=%d errno=%d (%s)\n",
				rc, errno, strerror(errno));
			return 1;
		}
	}
	close(fd);
	printf("[OK]\n");
	return 0;
}

static int check_openat(int dfd, const char *path, int flags)
{
	int fd;

	errno = 0;
	printf("Check success of openat(%d, '%s', %x)... ",
	       dfd, path?:"(null)", flags);
	fd = openat_(dfd, path, flags);
	return check_fd(fd);
}

static int check_open(const char *path, int flags)
{
	int fd;

	errno = 0;
	printf("Check success of open('%s', %x)... ", path?:"(null)", flags);
	fd = open_(path, flags, 0);
	return check_fd(fd);
}

static int check_fail(int rc, int expected_errno, const char *errno_str)
{
	if (rc > 0) {
		printf("[FAIL] (unexpected success from open operation)\n");
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

#define check_openat_fail(dfd, path, flags, errno)	\
	_check_openat_fail(dfd, path, flags, errno, #errno)
static int _check_openat_fail(int dfd, const char *path, int flags,
			      int expected_errno, const char *errno_str)
{
	int rc;

	printf("Check failure of openat(%d, '%s', %x) with %s... ",
		dfd, path?:"(null)", flags, errno_str);
	errno = 0;
	rc = openat_(dfd, path, flags);
	return check_fail(rc, expected_errno, errno_str);
}

#define check_open_fail(path, flags, errno)	\
	_check_open_fail(path, flags, errno, #errno)
static int _check_open_fail(const char *path, int flags,
			    int expected_errno, const char *errno_str)
{
	int rc;

	printf("Check failure of open('%s', %x) with %s... ",
	       path?:"(null)", flags, errno_str);
	errno = 0;
	rc = open_(path, flags, 0);
	return check_fail(rc, expected_errno, errno_str);
}

static int check_proc(void)
{
	int root_dfd = openat_(AT_FDCWD, "/", O_RDONLY);
	int proc_dfd = openat_(AT_FDCWD, "/proc/self", O_RDONLY);
	int fail = 0;

	if (proc_dfd < 0) {
		printf("'/proc/self' unavailable (errno=%d '%s'), skipping\n",
			errno, strerror(errno));
		return 0;
	}
	fail += check_openat(proc_dfd, "root/etc/passwd", O_RDONLY);
	fail += check_openat(root_dfd, "proc/self/root/etc/passwd", O_RDONLY);
#ifdef O_BENEATH
	fail += check_openat_fail(proc_dfd, "root/etc/passwd",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(root_dfd, "proc/self/root/etc/passwd",
				O_RDONLY|O_BENEATH, ENOTBENEATH);
#endif
	return fail;
}

#define check_setfl_ignored(fd, ignored_flag) \
	_check_setfl_ignored(fd, ignored_flag, #ignored_flag)
static int _check_setfl_ignored(int fd, int ignored_flag, const char *flagname)
{
	int flags;
	int newflags;
	int rc;

	printf("Check fcntl(%d, F_SETFL, +%s) is ignored... ", fd, flagname);
	flags = fcntl_(fd, F_GETFL, 0);
	if (flags == -1) {
		printf("[FAIL]: fcntl(F_GETFL) failed, rc=%d errno=%d (%s)\n",
		       flags, errno, strerror(errno));
		return 1;
	}
	if (flags & ignored_flag) {
		printf("[FAIL]: fcntl(F_GETFL) included %s (%x) in %x\n",
		       flagname, ignored_flag, flags);
		return 1;
	}
	rc = fcntl_(fd, F_SETFL, (flags | ignored_flag));
	if (rc == -1) {
		printf("[FAIL]: fcntl(F_SETFL) failed, rc=%d errno=%d (%s)\n",
		       rc, errno, strerror(errno));
		return 1;
	}
	newflags = fcntl_(fd, F_GETFL, 0);
	if (newflags != flags) {
		printf("[FAIL]: fcntl(F_SETFL) changed value of %s (%x) flag\n",
		       flagname, ignored_flag);
		return 1;
	}
	printf("[OK]\n");
	return 0;
}

static int check_setfl(void)
{
	int fd = open_("topfile", O_RDONLY|O_DIRECT, 0);
	int fail = 0;

	/* Attempts to set file creation flags are silently ignored. */
	fail += check_setfl_ignored(fd, O_CLOEXEC);
	fail += check_setfl_ignored(fd, O_CREAT);
	fail += check_setfl_ignored(fd, O_DIRECTORY);
	fail += check_setfl_ignored(fd, O_EXCL);
	fail += check_setfl_ignored(fd, O_NOCTTY);
	fail += check_setfl_ignored(fd, O_NOFOLLOW);
	fail += check_setfl_ignored(fd, O_TMPFILE);
	fail += check_setfl_ignored(fd, O_TRUNC);
#ifdef O_BENEATH
	fail += check_setfl_ignored(fd, O_BENEATH);
#endif

	close(fd);
	return fail;
}

static void prerequisites(void)
{
	int fd;
	const char *contents = "0123456789\n";

	mkdir("subdir", 0755);
	fd = open_("topfile", O_RDWR|O_CREAT|O_TRUNC, 0644);
	write(fd, contents, strlen(contents));
	close(fd);
	fd = open_("subdir/bottomfile", O_RDWR|O_CREAT|O_TRUNC, 0644);
	write(fd, contents, strlen(contents));
	close(fd);
	symlink("../topfile", "subdir/symlinkup");
	symlink("/etc/passwd", "subdir/symlinkout");
	symlink("bottomfile", "subdir/symlinkin");
	symlink("subdir/bottomfile", "symlinkdown");
}

int main(int argc, char *argv[])
{
	int fail = 0;
	int dot_dfd;
	int subdir_dfd;
	int file_fd;

	prerequisites();
	dot_dfd = openat_or_die(AT_FDCWD, ".", O_RDONLY);
	subdir_dfd = openat_or_die(AT_FDCWD, "subdir", O_RDONLY);
	file_fd = openat_or_die(AT_FDCWD, "topfile", O_RDONLY);

	/* Sanity check normal behavior */
	fail += check_open("topfile", O_RDONLY);
	fail += check_open("subdir/bottomfile", O_RDONLY);
	fail += check_openat(AT_FDCWD, "topfile", O_RDONLY);
	fail += check_openat(AT_FDCWD, "subdir/bottomfile", O_RDONLY);

	fail += check_openat(dot_dfd, "topfile", O_RDONLY);
	fail += check_openat(dot_dfd, "subdir/bottomfile", O_RDONLY);
	fail += check_openat(dot_dfd, "subdir/../topfile", O_RDONLY);
	fail += check_open("subdir/../topfile", O_RDONLY);

	fail += check_openat(subdir_dfd, "../topfile", O_RDONLY);
	fail += check_openat(subdir_dfd, "bottomfile", O_RDONLY);
	fail += check_openat(subdir_dfd, "../subdir/bottomfile", O_RDONLY);
	fail += check_openat(subdir_dfd, "symlinkup", O_RDONLY);
	fail += check_openat(subdir_dfd, "symlinkout", O_RDONLY);

	fail += check_open("/etc/passwd", O_RDONLY);
	fail += check_openat(AT_FDCWD, "/etc/passwd", O_RDONLY);
	fail += check_openat(dot_dfd, "/etc/passwd", O_RDONLY);
	fail += check_openat(subdir_dfd, "/etc/passwd", O_RDONLY);

	fail += check_openat_fail(AT_FDCWD, "bogus", O_RDONLY, ENOENT);
	fail += check_openat_fail(dot_dfd, "bogus", O_RDONLY, ENOENT);
	fail += check_openat_fail(999, "bogus", O_RDONLY, EBADF);
	fail += check_openat_fail(file_fd, "bogus", O_RDONLY, ENOTDIR);

#ifdef O_BENEATH
	/* Test out O_BENEATH */
	fail += check_open("topfile", O_RDONLY|O_BENEATH);
	fail += check_open("subdir/bottomfile", O_RDONLY|O_BENEATH);
	fail += check_openat(AT_FDCWD, "topfile", O_RDONLY|O_BENEATH);
	fail += check_openat(AT_FDCWD, "subdir/bottomfile",
			     O_RDONLY|O_BENEATH);

	fail += check_openat(dot_dfd, "topfile", O_RDONLY|O_BENEATH);
	fail += check_openat(dot_dfd, "subdir/bottomfile",
			     O_RDONLY|O_BENEATH);
	fail += check_openat(dot_dfd, "subdir///bottomfile",
			     O_RDONLY|O_BENEATH);
	fail += check_openat(subdir_dfd, "bottomfile", O_RDONLY|O_BENEATH);
	fail += check_openat(subdir_dfd, "./bottomfile", O_RDONLY|O_BENEATH);
	fail += check_openat(subdir_dfd, ".", O_RDONLY|O_BENEATH);

	/* Symlinks without .. or leading / are OK */
	fail += check_open("symlinkdown", O_RDONLY|O_BENEATH);
	fail += check_open("subdir/symlinkin", O_RDONLY|O_BENEATH);
	fail += check_openat(dot_dfd, "symlinkdown", O_RDONLY|O_BENEATH);
	fail += check_openat(dot_dfd, "subdir/symlinkin", O_RDONLY|O_BENEATH);
	fail += check_openat(subdir_dfd, "symlinkin", O_RDONLY|O_BENEATH);
	/* ... unless of course we specify O_NOFOLLOW */
	fail += check_open_fail("symlinkdown",
				O_RDONLY|O_BENEATH|O_NOFOLLOW, ELOOP);
	fail += check_open_fail("subdir/symlinkin",
				O_RDONLY|O_BENEATH|O_NOFOLLOW, ELOOP);
	fail += check_openat_fail(dot_dfd, "symlinkdown",
				  O_RDONLY|O_BENEATH|O_NOFOLLOW, ELOOP);
	fail += check_openat_fail(dot_dfd, "subdir/symlinkin",
				  O_RDONLY|O_BENEATH|O_NOFOLLOW, ELOOP);
	fail += check_openat_fail(subdir_dfd, "symlinkin",
				  O_RDONLY|O_BENEATH|O_NOFOLLOW, ELOOP);

	/* Can't open paths with ".." in them */
	fail += check_open_fail("subdir/../topfile",
				O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(dot_dfd, "subdir/../topfile",
				O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "../topfile",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "../subdir/bottomfile",
				O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "..", O_RDONLY|O_BENEATH,
				  ENOTBENEATH);

	/* Can't open paths starting with "/" */
	fail += check_open_fail("/etc/passwd", O_RDONLY|O_BENEATH,
				ENOTBENEATH);
	fail += check_openat_fail(AT_FDCWD, "/etc/passwd",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(dot_dfd, "/etc/passwd",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "/etc/passwd",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	/* Can't sneak around constraints with symlinks */
	fail += check_openat_fail(subdir_dfd, "symlinkup",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "symlinkout",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(subdir_dfd, "../symlinkdown",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_openat_fail(dot_dfd, "subdir/symlinkup",
				  O_RDONLY|O_BENEATH, ENOTBENEATH);
	fail += check_open_fail("subdir/symlinkup", O_RDONLY|O_BENEATH,
				ENOTBENEATH);
#else
	printf("Skipping O_BENEATH tests due to missing #define\n");
#endif
	fail += check_proc();
	fail += check_setfl();

	if (fail > 0)
		printf("%d tests failed\n", fail);
	return fail;
}
