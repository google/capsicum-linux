#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

#include <linux/types.h>

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
#define CLONE_NEWNS	0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

/*
 * Old flags, unused by current clone.  clone does not return EINVAL for these
 * flags, so they can't easily be reused.  clone4 can use them.
 */
#define CLONE_PID	0x00001000
#define CLONE_DETACHED	0x00400000
#define CLONE_STOPPED	0x02000000

/*
 * Flags that only work with clone4.
 */
#define CLONE_AUTOREAP	0x00001000	/* Automatically reap the process */

#ifdef __KERNEL__
/*
 * Valid flags for clone and for clone4. Kept in this file next to the flag
 * list above, but not exposed to userspace.
 */
#define CLONE_VALID_FLAGS	(0xffffffffULL & ~(CLONE_PID | CLONE_DETACHED | CLONE_STOPPED))
#define CLONE4_VALID_FLAGS	(CLONE_VALID_FLAGS | CLONE_AUTOREAP)
#endif /* __KERNEL__ */

/*
 * Structure passed to clone4 for additional arguments.  Initialized to 0,
 * then overwritten with arguments from userspace, so arguments not supplied by
 * userspace will remain 0.  New versions of the kernel may safely append new
 * arguments to the end.
 */
struct clone4_args {
	__kernel_pid_t __user *ptid;
	__kernel_pid_t __user *ctid;
	__kernel_ulong_t stack_start;
	__kernel_ulong_t stack_size;
	__kernel_ulong_t tls;
};

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5
#define SCHED_DEADLINE		6

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000

/*
 * For the sched_{set,get}attr() calls
 */
#define SCHED_FLAG_RESET_ON_FORK	0x01

#endif /* _UAPI_LINUX_SCHED_H */
