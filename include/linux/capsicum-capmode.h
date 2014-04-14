#ifndef _LINUX_CAPSICUM_CAPMODE_H
#define _LINUX_CAPSICUM_CAPMODE_H

#ifdef CONFIG_SECURITY_CAPSICUM
#include <linux/seccomp.h>
#include <linux/sched.h>

static inline bool capsicum_in_cap_mode(void)
{
	return test_thread_flag(TIF_SECCOMP) &&
	       current->seccomp.mode == SECCOMP_MODE_LSM;
}
#else
#define capsicum_in_cap_mode()	false
#endif

/* LSM hook fallback functions */
int capsicum_intercept_syscall(int arch, int callnr, unsigned long *args);

#endif /* _LINUX_CAPSICUM_CAPMODE_H */
