#ifndef _LINUX_CAPSICUM_H
#define _LINUX_CAPSICUM_H

#include <uapi/linux/capsicum.h>

struct file;

/* LSM hook fallback functions */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);
struct file *capsicum_file_lookup(struct file *file,
				  cap_rights_t required_rights,
				cap_rights_t *actual_rights);
struct file *capsicum_file_install(cap_rights_t base_rights, struct file *file);
#ifdef CONFIG_SECURITY_PATH
struct dentry;
int capsicum_path_lookup(cap_rights_t base_rights,
			struct dentry *dentry, const char *name);

#ifdef CONFIG_SECURITY_CAPSICUM
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

#endif

#endif /* _LINUX_SECCOMP_H */
