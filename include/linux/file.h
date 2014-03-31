/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/posix_types.h>
#include <linux/err.h>
#include <linux/capsicum.h>

struct file;

extern void fput(struct file *);

struct file_operations;
struct vfsmount;
struct dentry;
struct path;
extern struct file *alloc_file(struct path *, fmode_t mode,
	const struct file_operations *fop);

static inline void fput_light(struct file *file, int fput_needed)
{
	if (fput_needed)
		fput(file);
}

struct fd {
	struct file *file;
	unsigned int flags;
};
#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

static inline void fdput(struct fd fd)
{
	if (fd.flags & FDPUT_FPUT)
		fput(fd.file);
}

extern struct file *fget(unsigned int fd);
extern struct file *fget_raw(unsigned int fd);
extern unsigned long __fdget(unsigned int fd);
extern unsigned long __fdget_raw(unsigned int fd);
extern unsigned long __fdget_pos(unsigned int fd);

static inline struct fd __to_fd(unsigned long v)
{
	return (struct fd){(struct file *)(v & ~3),v & 3};
}

static inline struct fd fdget(unsigned int fd)
{
	return __to_fd(__fdget(fd));
}

static inline struct fd fdget_raw(unsigned int fd)
{
	return __to_fd(__fdget_raw(fd));
}

static inline struct fd fdget_pos(unsigned int fd)
{
	return __to_fd(__fdget_pos(fd));
}

#ifdef CONFIG_SECURITY_CAPSICUM
/*
 * fget() variants that check that the FD has particular rights associated with
 * it, specified as a full capsicum_rights structure.
 */
extern struct file *fget_rights(unsigned int fd,
				const struct capsicum_rights *rights);
extern struct file *fget_raw_rights(unsigned int fd,
				    const struct capsicum_rights *rights);
extern struct fd fdget_rights(unsigned int fd,
			      const struct capsicum_rights *rights);
/*
 * The fdget_raw_rights variant also optionally returns the complete set of
 * rights associated with the file descriptor.
 */
extern struct fd fdget_raw_rights(unsigned int fd,
				  const struct capsicum_rights **actual_rights,
				  const struct capsicum_rights *rights);

/*
 * fget() variants that check that the FD has particular rights associated with
 * it, specified as a varargs list of primary rights.
 */
#define fgetr(fd, ...)		_fgetr((fd), __VA_ARGS__, CAP_LIST_END)
#define fgetr_raw(fd, ...)	_fgetr_raw((fd), __VA_ARGS__, CAP_LIST_END)
#define fdgetr(fd, ...)	_fdgetr((fd), __VA_ARGS__, CAP_LIST_END)
#define fdgetr_raw(fd, ...)	_fdgetr_raw((fd), __VA_ARGS__, CAP_LIST_END)
#define fdgetr_pos(fd, ...)	_fdgetr_pos((fd), __VA_ARGS__, CAP_LIST_END)
extern struct file *_fgetr(unsigned int fd, ...);
extern struct file *_fgetr_raw(unsigned int fd, ...);
extern struct fd _fdgetr(unsigned int fd, ...);
extern struct fd _fdgetr_raw(unsigned int fd, ...);
extern struct fd _fdgetr_pos(unsigned int fd, ...);

#else
/*
 * In a non-Capsicum build, all rights-checking fget() variants fall back to the
 * normal versions (but still return errors as ERR_PTR values not just NULL).
 */
static inline struct file *fget_rights(unsigned int fd,
				       const struct capsicum_rights *rights)
{
	return fget(fd) ?: ERR_PTR(-EBADF);
}
static inline struct file *fget_raw_rights(unsigned int fd,
					   const struct capsicum_rights *rights)
{
	return fget_raw(fd) ?: ERR_PTR(-EBADF);
}
static inline struct fd fdget_rights(unsigned int fd,
				     const struct capsicum_rights *rights)
{
	struct fd f = fdget(fd);
	if (f.file == NULL)
		f.file = ERR_PTR(-EBADF);
	return f;
}
static inline struct fd
fdget_raw_rights(unsigned int fd,
		 const struct capsicum_rights **actual_rights,
		 const struct capsicum_rights *rights)
{
	struct fd f = fdget_raw(fd);
	if (f.file == NULL)
		f.file = ERR_PTR(-EBADF);
	return f;
}

#define fgetr(fd, ...)		(fget(fd) ?: ERR_PTR(-EBADF))
#define fgetr_raw(fd, ...)	(fget_raw(fd) ?: ERR_PTR(-EBADF))
#define fdgetr(fd, ...)	fdget_rights((fd), NULL)
#define fdgetr_raw(fd, ...)	fdget_raw_rights((fd), NULL, NULL)
static inline struct fd fdgetr_pos(int fd, ...)
{
	struct fd f = fdget_pos(fd);
	if (f.file == NULL)
		f.file = ERR_PTR(-EBADF);
	return f;
}
#endif

extern int f_dupfd(unsigned int from, struct file *file, unsigned flags);
extern int replace_fd(unsigned fd, struct file *file, unsigned flags);
extern void set_close_on_exec(unsigned int fd, int flag);
extern bool get_close_on_exec(unsigned int fd);
extern void put_filp(struct file *);
extern int get_unused_fd_flags(unsigned flags);
#define get_unused_fd() get_unused_fd_flags(0)
extern void put_unused_fd(unsigned int fd);

extern void fd_install(unsigned int fd, struct file *file);

extern void flush_delayed_fput(void);
extern void __fput_sync(struct file *);

#endif /* __LINUX_FILE_H */
