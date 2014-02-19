#ifndef _LINUX_CAPSICUM_H
#define _LINUX_CAPSICUM_H

#include <stdarg.h>
#include <uapi/linux/capsicum.h>

struct file;

/* LSM hook fallback functions */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);
struct file *capsicum_file_lookup(struct file *file,
				  struct cap_rights *required_rights,
				  struct cap_rights *actual_rights);
struct file *capsicum_file_install(struct cap_rights *base_rights, struct file *file);
#ifdef CONFIG_SECURITY_PATH
struct dentry;
int capsicum_path_lookup(struct cap_rights *base_rights,
			 struct dentry *dentry, const char *name);

#ifdef CONFIG_SECURITY_CAPSICUM
/* Determine if a file is a Capsicum capability. */
int capsicum_is_cap(const struct file *file);

/* Restrict the rights associated with a file descriptor. */
int capsicum_rights_limit(unsigned int fd, struct cap_rights *new_rights);

/* Return the underlying file for a Capsicum capability. */
struct file *capsicum_unwrap(const struct file *capf, struct cap_rights *rights);

/* Rights manipulation functions */
#define cap_rights_init(rights, ...) \
	_cap_rights_init((rights), __VA_ARGS__, 0ULL)
#define cap_rights_set(rights, ...) \
	_cap_rights_set((rights), __VA_ARGS__, 0ULL)
#define cap_rights_clear(rights, ...) \
	_cap_rights_clear((rights), __VA_ARGS__, 0ULL)
#define cap_rights_is_set(rights, ...) \
	_cap_rights_is_set((rights), __VA_ARGS__, 0ULL)

struct cap_rights *_cap_rights_init(struct cap_rights *rights, ...);
struct cap_rights *_cap_rights_set(struct cap_rights *rights, ...);
struct cap_rights *_cap_rights_clear(struct cap_rights *rights, ...);
bool _cap_rights_is_set(const struct cap_rights *rights, ...);

bool cap_rights_is_valid(const struct cap_rights *rights);
struct cap_rights *cap_rights_merge(struct cap_rights *dst, const struct cap_rights *src);
struct cap_rights *cap_rights_remove(struct cap_rights *dst, const struct cap_rights *src);
bool cap_rights_contains(const struct cap_rights *big, const struct cap_rights *little);

#else

#define cap_rights_init(rights, ...) (rights)
#define cap_rights_set(rights, ...) (rights)
#define cap_rights_clear(rights, ...) (rights)
#define cap_rights_is_set(rights, ...) (rights)

#endif

#endif

#endif /* _LINUX_SECCOMP_H */
