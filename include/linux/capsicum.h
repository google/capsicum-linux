#ifndef _LINUX_CAPSICUM_H
#define _LINUX_CAPSICUM_H

#include <stdarg.h>
#include <uapi/linux/capsicum.h>

struct file;
/* Complete rights structure (primary and subrights). */
struct capsicum_rights {
	struct cap_rights primary;
	unsigned int fcntls;  /* Only valid if CAP_FCNTL set in primary. */
	int nioctls;  /* -1=>all; only valid if CAP_IOCTL set in primary */
	unsigned int *ioctls;
};

/* LSM hook fallback functions */
struct file *capsicum_file_lookup(struct file *file,
				  const struct capsicum_rights *required_rights,
				  const struct capsicum_rights **actual_rights);
struct file *capsicum_file_install(const struct capsicum_rights *base_rights,
				   struct file *file);
#ifdef CONFIG_SECURITY_PATH
struct dentry;
int capsicum_path_lookup(const struct capsicum_rights *base_rights,
			 struct dentry *dentry, const char *name);
#endif

#define CAP_LIST_END	0ULL

#ifdef CONFIG_SECURITY_CAPSICUM
/* Rights manipulation functions */
#define cap_rights_init(rights, ...) \
	_cap_rights_init((rights), __VA_ARGS__, CAP_LIST_END)
#define cap_rights_set(rights, ...) \
	_cap_rights_set((rights), __VA_ARGS__, CAP_LIST_END)
struct capsicum_rights *_cap_rights_init(struct capsicum_rights *rights, ...);
struct capsicum_rights *_cap_rights_set(struct capsicum_rights *rights, ...);
struct capsicum_rights *cap_rights_vinit(struct capsicum_rights *rights,
					 va_list ap);
struct capsicum_rights *cap_rights_vset(struct capsicum_rights *rights,
					va_list ap);
struct capsicum_rights *cap_rights_set_all(struct capsicum_rights *rights);

#else

#define cap_rights_init(rights, ...) _cap_rights_noop(rights)
#define cap_rights_set(rights, ...) _cap_rights_noop(rights)
#define cap_rights_set_all(rights) _cap_rights_noop(rights)
static inline struct capsicum_rights *
_cap_rights_noop(struct capsicum_rights *rights)
{
	return rights;
}

#endif

#endif /* _LINUX_CAPSICUM_H */
