#ifndef _CLONETEST_H_
#define _CLONETEST_H_

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

/*
 * Copies of structures and constants from <linux/sched.h>; we cannot include
 * that file because it pulls in various structure definitions (timespec,
 * timeval etc) that clash with normal userspace definitions.
 */
struct clone4_args {
	pid_t *ptid;
	pid_t *ctid;
	void *stack_start;
	void *stack_size;
	void *tls;
	int *clonefd;
	uint32_t clonefd_flags;
};

struct clonefd_info {
	int32_t code;
	int32_t status;
	uint64_t utime;
	uint64_t stime;
};

#define STACK_SIZE (1*1024*1024)

/* System call accessors */
static inline pid_t gettid_(void)
{
	return syscall(__NR_gettid);
}

extern const char *verbose;

#define vprintf(...) do {if (verbose) printf(__VA_ARGS__); } while (0)
#define EXPECT(cond) do { \
	if (!(cond)) { \
		printf("%s:%d: expectation '%s' failed\n", \
		       __FILE__, __LINE__, #cond); \
		fail++; \
	} \
} while (0)
#define ASSERT(cond) do { \
	if (!(cond)) { \
		printf("%s:%d: expectation '%s' failed\n", \
		       __FILE__, __LINE__, #cond); \
		fail++; \
		return fail; \
	} \
} while (0)

static inline int pid_present(pid_t pid)
{
	struct stat sb;
	char buffer[128];

	sprintf(buffer, "/proc/%d", pid);
	return ((stat(buffer, &sb) == 0) && S_ISDIR(sb.st_mode));
}

static inline int nonparent_ptrace_allowed(void)
{
	/*
	 * Some Yama LSM configurations disallow ptrace
	 * from non-parents.  Either run as root or change
	 * /proc/sys/kernel/yama/ptrace_scope to be 0.
	 */
	const char *name = "/proc/sys/kernel/yama/ptrace_scope";
	int fd = open(name, O_RDONLY);
	char value = '0';

	if (fd < 0)
		return 1;
	read(fd, &value, 1);
	close(fd);
	if (value == '0')
		return 1;
	printf("('%s' has value '%c') ", name, value);
	return 0;
}

/* Child process functions */
static inline int child_just_exit(void *data)
{
	vprintf("  [%d] child exiting\n", gettid_());
	return 0;
}

static inline int child_wait_then_exit(void *data)
{
	vprintf("  [%d] child waiting\n", gettid_());
	sleep(1);
	vprintf("  [%d] child exiting\n", gettid_());
	return 0;
}

static inline int child_loop_forever(void *data)
{
	int count = 30;  /* well, almost forever */

	vprintf("  [%d] child starts looping\n", gettid_());
	while (count--) {
		sleep(1);
		vprintf("  [%d] I aten't dead\n", gettid_());
	}
	return 1;
}

#endif
