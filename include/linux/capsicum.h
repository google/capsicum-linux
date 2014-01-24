#ifndef _LINUX_CAPSICUM_H
#define _LINUX_CAPSICUM_H

#include <uapi/linux/capsicum.h>

#ifdef CONFIG_SECURITY_CAPSICUM
struct file;

/*
 * Process the arguments for a syscall and return the action that the seccomp
 * framework should perform for the syscall.
 */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);

/*
 * Wrap a file in a new Capsicum capability object and install the capability
 * object into the file descriptor table. Return the new file descriptor or an
 * error value.
 */
int capsicum_install_fd(struct file *orig, cap_rights_t rights);

/* Determine if a file is a Capsicum capability. */
int capsicum_is_cap(const struct file *file);

/* Return the underlying file for a Capsicum capability. */
struct file *capsicum_unwrap(const struct file *capf, cap_rights_t *rights);

#endif

#endif /* _LINUX_SECCOMP_H */
