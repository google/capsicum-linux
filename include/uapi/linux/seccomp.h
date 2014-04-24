#ifndef _UAPI_LINUX_SECCOMP_H
#define _UAPI_LINUX_SECCOMP_H

#include <linux/compiler.h>
#include <linux/types.h>


/* Valid bitmask values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
#define SECCOMP_MODE_DISABLED	0x00 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT	0x01 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER	0x02 /* uses user-supplied filter. */
#define SECCOMP_MODE_LSM	0x04 /* uses LSM hook to filter. */

#define SECCOMP_MODE_VALID	0x07 /* mask of valid mode values. */

/* Valid extension types as arg2 for prctl(PR_SECCOMP_EXT) */
#define SECCOMP_EXT_ACT		1

/* Valid extension actions as arg3 to prctl(PR_SECCOMP_EXT, SECCOMP_EXT_ACT) */
#define SECCOMP_EXT_ACT_FILTER		1 /* apply seccomp-bpf filter with flags */
#define SECCOMP_EXT_ACT_TSYNC		2 /* synchronize threadgroup filters */
#define SECCOMP_EXT_ACT_LSM		3 /* apply LSM hook filter with flags */
#define SECCOMP_EXT_ACT_TSYNC_LSM	4 /* synchronize LSM hook status */

/* Flags for prctl arg4 when calling SECCOMP_EXT_ACT_FILTER */
#define SECCOMP_FILTER_TSYNC	1 /* synchronize threadgroup to filter */

/* Flags for prctl arg4 when calling SECCOMP_EXT_ACT_LSM */
#define SECCOMP_LSM_TSYNC	1 /* synchronize threadgroup seccomp status */

/*
 * All BPF programs must return a 32-bit value.
 * The bottom 16-bits are for optional return data.
 * The upper 16-bits are ordered from least permissive values to most.
 *
 * The ordering ensures that a min_t() over composed return values always
 * selects the least permissive choice.
 */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
#define SECCOMP_RET_TRACE	0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU

/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

#endif /* _UAPI_LINUX_SECCOMP_H */
