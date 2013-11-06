#ifndef _LINUX_CAPSICUM_H
#define _LINUX_CAPSICUM_H

#include <uapi/linux/capsicum.h>

#ifdef CONFIG_SECURITY_CAPSICUM
extern int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);
#endif

#endif /* _LINUX_SECCOMP_H */
