/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Copyright (C) 2012 Google, Inc.
 * Will Drewry <wad@chromium.org>
 *
 * This defines a simple but solid secure-computing facility.
 *
 * Mode 0x01 uses a fixed list of allowed system calls.
 * Mode 0x02 allows user-defined system call filters in the form
 *        of Berkeley Packet Filters/Linux Socket Filters.
 * Mode 0x04 allows the LSM to filter system calls.
 * If multiple modes are enabled, the most restrictive result is
 * used.
 */

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/capsicum-capmode.h>

/* #define SECCOMP_DEBUG 1 */

#ifdef CONFIG_SECCOMP_FILTER
#include <asm/syscall.h>
#include <linux/filter.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>

static long seccomp_set_mode(unsigned long mode, char * __user filter);

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @len: the number of instructions in the program
 * @insnsi: the BPF program instructions to evaluate
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	atomic_t usage;
	struct seccomp_filter *prev;
	struct sk_filter *prog;
};

/* Limit any path through the tree to 256KB worth of instructions. */
#define MAX_INSNS_PER_PATH ((1 << 18) / sizeof(struct sock_filter))

/*
 * Endianness is explicitly ignored and left for BPF program authors to manage
 * as per the specific architecture.
 */
static void populate_seccomp_data(struct seccomp_data *sd)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);
	unsigned long args[6];

	sd->nr = syscall_get_nr(task, regs);
	sd->arch = syscall_get_arch();
	syscall_get_arguments(task, regs, 0, 6, args);
	sd->args[0] = args[0];
	sd->args[1] = args[1];
	sd->args[2] = args[2];
	sd->args[3] = args[3];
	sd->args[4] = args[4];
	sd->args[5] = args[5];
	sd->instruction_pointer = KSTK_EIP(task);
	sd->tgid = task_tgid_vnr(current);
	sd->tid = task_pid_vnr(current);
}

/**
 *	seccomp_check_filter - verify seccomp filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Takes a previously checked filter (by sk_chk_filter) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen)
{
	int pc;
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_LD | BPF_W | BPF_ABS:
			ftest->code = BPF_LDX | BPF_W | BPF_ABS;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct seccomp_data) || k & 3)
				return -EINVAL;
			continue;
		case BPF_LD | BPF_W | BPF_LEN:
			ftest->code = BPF_LD | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		case BPF_LDX | BPF_W | BPF_LEN:
			ftest->code = BPF_LDX | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_RET | BPF_K:
		case BPF_RET | BPF_A:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
		case BPF_MISC | BPF_TAX:
		case BPF_MISC | BPF_TXA:
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
		case BPF_JMP | BPF_JA:
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * seccomp_run_filters - evaluates all seccomp filters against @syscall
 * @syscall: number of the current system call
 *
 * Returns valid seccomp BPF response codes.
 */
static u32 seccomp_run_filters(int syscall)
{
	struct seccomp_filter *f = ACCESS_ONCE(current->seccomp.filter);
	struct seccomp_data sd;
	u32 ret = SECCOMP_RET_ALLOW;

	/* Ensure unexpected behavior doesn't result in failing open. */
	if (WARN_ON(f == NULL))
		return SECCOMP_RET_KILL;

	populate_seccomp_data(&sd);

	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	for (; f; f = ACCESS_ONCE(f->prev)) {
		u32 cur_ret = SK_RUN_FILTER(f->prog, (void *)&sd);

		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}
	return ret;
}

/*
 * Check whether the task has CAP_SYS_ADMIN in its namespace or is running with
 * no_new_privs.
 */
static inline bool seccomp_has_no_new_privs(void)
{
	return task_no_new_privs(current) ||
	       (security_capable_noaudit(current_cred(), current_user_ns(),
					CAP_SYS_ADMIN) == 0);
}

/* Returns 1 if the candidate is an ancestor. */
static int is_ancestor(struct seccomp_filter *candidate,
		       struct seccomp_filter *child)
{
	/* NULL is the root ancestor. */
	if (candidate == NULL)
		return 1;
	for (; child; child = child->prev)
		if (child == candidate)
			return 1;
	return 0;
}

/* Expects locking and sync suitability to have been done already. */
static void seccomp_sync_thread_filter(struct task_struct *caller,
				       struct task_struct *thread)
{
	/* Get a task reference for the new leaf node. */
	get_seccomp_filter(caller);
	/*
	 * Drop the task reference to the shared ancestor since
	 * current's path will hold a reference.  (This also
	 * allows a put before the assignment.)
	 */
	put_seccomp_filter(thread);
	thread->seccomp.filter = caller->seccomp.filter;
	/* Opt the other thread into seccomp if needed.
	 * As threads are considered to be trust-realm
	 * equivalent (see ptrace_may_access), it is safe to
	 * allow one thread to transition the other.
	 */
	if (!(thread->seccomp.mode & SECCOMP_MODE_FILTER)) {
		thread->seccomp.mode |= SECCOMP_MODE_FILTER;
		/*
		 * Don't let an unprivileged task work around
		 * the no_new_privs restriction by creating
		 * a thread that sets it up, enters seccomp,
		 * then dies.
		 */
		if (task_no_new_privs(caller))
			task_set_no_new_privs(thread);
		set_tsk_thread_flag(thread, TIF_SECCOMP);
	}
}

/**
 * seccomp_act_sync_threads_filter: sets all threads to use current's filter
 *
 * Returns 0 on success, -ve on error, or the pid of a thread which was
 * either not in the correct seccomp mode or it did not have an ancestral
 * seccomp filter.
 */
static pid_t seccomp_act_sync_threads_filter(void)
{
	struct task_struct *thread, *caller;
	unsigned long tflags;
	pid_t failed = 0;

	if (!(current->seccomp.mode & SECCOMP_MODE_FILTER))
		return -EACCES;

	write_lock_irqsave(&tasklist_lock, tflags);
	thread = caller = current;
	while_each_thread(caller, thread) {
		unsigned long irqflags;
		seccomp_lock(thread, &irqflags);
		/*
		 * Validate thread being eligible for synchronization.
		 */
		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED ||
		    ((thread->seccomp.mode & SECCOMP_MODE_FILTER) &&
		     is_ancestor(thread->seccomp.filter,
				 caller->seccomp.filter))) {
			seccomp_sync_thread_filter(caller, thread);
		} else {
			/* Keep the last sibling that failed to return. */
			failed = task_pid_vnr(thread);
			/* If the pid cannot be resolved, then return -ESRCH */
			if (failed == 0)
				failed = -ESRCH;
		}
		seccomp_unlock(thread, irqflags);
	}
	write_unlock_irqrestore(&tasklist_lock, tflags);
	return failed;
}

#ifdef CONFIG_SECCOMP_CAPSICUM
/* Expects locking to have been done already. */
static void seccomp_sync_thread_capsicum(struct task_struct *caller,
					 struct task_struct *thread)
{
	/* Opt the other thread into seccomp if needed.
	 * As threads are considered to be trust-realm
	 * equivalent (see ptrace_may_access), it is safe to
	 * allow one thread to transition the other.
	 */
	if (!(thread->seccomp.mode & SECCOMP_MODE_CAPSICUM)) {
		thread->seccomp.mode |= SECCOMP_MODE_CAPSICUM;
		/*
		 * Don't let an unprivileged task work around
		 * the no_new_privs restriction by creating
		 * a thread that sets it up, enters seccomp,
		 * then dies.
		 */
		if (task_no_new_privs(caller))
			task_set_no_new_privs(thread);
		set_tsk_thread_flag(thread, TIF_SECCOMP);
	}
}

/**
 * seccomp_act_sync_threads_capsicum: sets all threads to use current's LSM mode
 *
 * Returns 0 on success, -ve on error.
 */
static long seccomp_act_sync_threads_capsicum(void)
{
	unsigned long tflags;
	struct task_struct *thread, *caller;

	if (!(current->seccomp.mode & SECCOMP_MODE_CAPSICUM))
		return -EACCES;

	write_lock_irqsave(&tasklist_lock, tflags);
	thread = caller = current;
	while_each_thread(caller, thread) {
		unsigned long irqflags;
		seccomp_lock(thread, &irqflags);
		seccomp_sync_thread_capsicum(caller, thread);
		seccomp_unlock(thread, irqflags);
	}
	write_unlock_irqrestore(&tasklist_lock, tflags);
	return 0;
}
#endif

/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog)
{
	struct seccomp_filter *filter;
	unsigned long fp_size = fprog->len * sizeof(struct sock_filter);
	struct sock_filter *fp;
	int new_len;
	long ret;

	if (fprog->len == 0 || fprog->len > BPF_MAXINSNS)
		return ERR_PTR(-EINVAL);

	/*
	 * Installing a seccomp filter requires that the task has
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.
	 */
	if (!seccomp_has_no_new_privs())
		return ERR_PTR(-EACCES);

	fp = kzalloc(fp_size, GFP_KERNEL|__GFP_NOWARN);
	if (!fp)
		return ERR_PTR(-ENOMEM);

	/* Copy the instructions from fprog. */
	ret = -EFAULT;
	if (copy_from_user(fp, fprog->filter, fp_size))
		goto free_prog;

	/* Check and rewrite the fprog via the skb checker */
	ret = sk_chk_filter(fp, fprog->len);
	if (ret)
		goto free_prog;

	/* Check and rewrite the fprog for seccomp use */
	ret = seccomp_check_filter(fp, fprog->len);
	if (ret)
		goto free_prog;

	/* Convert 'sock_filter' insns to 'sock_filter_int' insns */
	ret = sk_convert_filter(fp, fprog->len, NULL, &new_len);
	if (ret)
		goto free_prog;

	/* Allocate a new seccomp_filter */
	ret = -ENOMEM;
	filter = kzalloc(sizeof(struct seccomp_filter),
			 GFP_KERNEL|__GFP_NOWARN);
	if (!filter)
		goto free_prog;

	filter->prog = kzalloc(sk_filter_size(new_len),
			       GFP_KERNEL|__GFP_NOWARN);
	if (!filter->prog)
		goto free_filter;

	ret = sk_convert_filter(fp, fprog->len, filter->prog->insnsi, &new_len);
	if (ret)
		goto free_filter_prog;
	kfree(fp);

	atomic_set(&filter->usage, 1);
	filter->prog->len = new_len;

	sk_filter_select_runtime(filter->prog);

	return filter;

free_filter_prog:
	kfree(filter->prog);
free_filter:
	kfree(filter);
free_prog:
	kfree(fp);
	return ERR_PTR(ret);
}

/**
 * seccomp_prepare_user_filter - prepares a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
+ * Returns filter on success and ERR_PTR otherwise.
*/
static struct seccomp_filter *
seccomp_prepare_user_filter(char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}

/**
 * _seccomp_attach_filter: validated and attach filter
 * @filter: seccomp filter to add to the current process
 *
 * Caller must be holding the seccomp lock.
 *
 * Returns 0 on success, -ve on error.
 */
static long _seccomp_attach_filter(struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;

	BUG_ON(!spin_is_locked(&current->seccomp.lock));

	/* Validate resulting filter length. */
	total_insns = filter->prog->len;
	for (walker = current->seccomp.filter; walker; walker = filter->prev)
		total_insns += walker->prog->len + 4;  /* include a 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;

	return 0;
}

/**
 * seccomp_act_filter: attach filter with additional flags
 * @flags:  flags from SECCOMP_FILTER_* to change behavior
 * @filter: struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * Return 0 on success, -ve on error, or thread pid that caused failures.
 */
static long seccomp_act_filter(unsigned long flags, char * __user filter)
{
	long ret;

	/* Only SECCOMP_FILTER_TSYNC is recognized. */
	if ((flags & ~(SECCOMP_FILTER_TSYNC)) != 0)
		return -EINVAL;

	ret = seccomp_set_mode(SECCOMP_MODE_FILTER, filter);
	if (ret)
		return ret;

	if (flags & SECCOMP_FILTER_TSYNC)
		return seccomp_act_sync_threads_filter();

	return 0;
}

#ifdef CONFIG_SECCOMP_CAPSICUM
/**
 * seccomp_act_capsicum: enable LSM mode with additional flags
 * @flags:  flags from SECCOMP_CAPSICUM_* to change behavior
 *
 * Return 0 on success, -ve on error.
 */
static long seccomp_act_capsicum(unsigned long flags)
{
	long ret;

	/* Only SECCOMP_CAPSICUM_TSYNC is recognized. */
	if ((flags & ~(SECCOMP_CAPSICUM_TSYNC)) != 0)
		return -EINVAL;

	ret = seccomp_set_mode(SECCOMP_MODE_CAPSICUM, NULL);
	if (ret)
		return ret;

	if (flags & SECCOMP_CAPSICUM_TSYNC)
		return seccomp_act_sync_threads_capsicum();

	return 0;
}
#endif

/**
 * seccomp_extended_action: performs the specific action
 * @action: the enum of the action to perform.
 *
 * Returns 0 on success. On failure, it returns != 0, or EINVAL on an
 * invalid action.
 */
static long seccomp_extended_action(int action, unsigned long arg1,
				    unsigned long arg2)
{
	switch (action) {
	case SECCOMP_EXT_ACT_FILTER:
		return seccomp_act_filter(arg1, (char * __user)arg2);
	case SECCOMP_EXT_ACT_TSYNC:
		/* arg1 and arg2 are currently unused. */
		if (arg1 || arg2)
			return -EINVAL;
		return seccomp_act_sync_threads_filter();
#ifdef CONFIG_SECCOMP_CAPSICUM
	case SECCOMP_EXT_ACT_CAPSICUM:
		/* arg2 is currently unused. */
		if (arg2)
			return -EINVAL;
		return seccomp_act_capsicum(arg1);
	case SECCOMP_EXT_ACT_TSYNC_CAPSICUM:
		/* arg1 and arg2 are currently unused. */
		if (arg1 || arg2)
			return -EINVAL;
		return seccomp_act_sync_threads_capsicum();
#endif
	default:
		break;
	}
	return -EINVAL;
}

/* get_seccomp_filter - increments the reference count of the filter on @tsk */
void get_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = ACCESS_ONCE(tsk->seccomp.filter);
	if (!orig)
		return;
	/* Reference count is bounded by the number of total processes. */
	atomic_inc(&orig->usage);
}

/* put_seccomp_filter - decrements the ref count of tsk->seccomp.filter */
void put_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct seccomp_filter *freeme = orig;
		orig = ACCESS_ONCE(orig->prev);
		sk_filter_free(freeme->prog);
		kfree(freeme);
	}
}

/**
 * seccomp_send_sigsys - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
static void seccomp_send_sigsys(int syscall, int reason)
{
	struct siginfo info;
	memset(&info, 0, sizeof(info));
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch();
	info.si_syscall = syscall;
	force_sig_info(SIGSYS, &info, current);
}

/**
 * prctl_seccomp_ext: exposed extension behaviors for seccomp
 * @cmd: the type of extension being called
 * @arg[123]: the arguments for the extension
 *
 * Returns == 0 on success and != 0 on failure.
 * Invalid arguments return -EINVAL.
 */
long prctl_seccomp_ext(unsigned long type, unsigned long arg1,
		       unsigned long arg2, unsigned long arg3)
{
	if (type != SECCOMP_EXT_ACT)
		return -EINVAL;
	/* For action extensions, arg1 is the identifier. */
	return seccomp_extended_action(arg1, arg2, arg3);
}
#endif	/* CONFIG_SECCOMP_FILTER */

/*
 * Secure computing mode 0x01 allows only read/write/exit/sigreturn.
 * To be fully secure this must be combined with rlimit
 * to limit the stack allocations too.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

static u32 secure_computing_mode1(int this_syscall)
{
	int *syscall = mode1_syscalls;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		syscall = mode1_syscalls_32;
#endif
	do {
		if (*syscall == this_syscall)
			return SECCOMP_RET_ALLOW;
	} while (*++syscall);
	return SECCOMP_RET_KILL;
}

#ifdef CONFIG_SECCOMP_CAPSICUM
static u32 secure_computing_capsicum(int this_syscall)
{
	unsigned long args[6];
	struct pt_regs *regs = task_pt_regs(current);
	int arch = syscall_get_arch();
	syscall_get_arguments(current, regs, 0, 6, args);
	return capsicum_intercept_syscall(arch, this_syscall, args);
}
#endif

int __secure_computing(int this_syscall)
{
	int modeset = current->seccomp.mode;
	int mode;
	int exit_sig = 0;
	u32 ret = SECCOMP_RET_ALLOW;
	u32 cur_ret;
	int data;
#if defined(CONFIG_SECCOMP_FILTER) || defined(CONFIG_SECCOMP_CAPSICUM)
	struct pt_regs *regs = task_pt_regs(current);
#endif

	for (mode = 0x01; (mode & SECCOMP_MODE_VALID); mode <<= 1) {
		if (!(modeset & mode))
			continue;
		switch (mode) {
		case SECCOMP_MODE_STRICT:
			cur_ret = secure_computing_mode1(this_syscall);
			exit_sig = SIGKILL;
			break;
#ifdef CONFIG_SECCOMP_FILTER
		case SECCOMP_MODE_FILTER:
			cur_ret = seccomp_run_filters(this_syscall);
			break;
#endif
#ifdef CONFIG_SECCOMP_CAPSICUM
		case SECCOMP_MODE_CAPSICUM:
			cur_ret = secure_computing_capsicum(this_syscall);
			break;
#endif
		default:
			BUG();
		}
		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}

	data = ret & SECCOMP_RET_DATA;
	ret &= SECCOMP_RET_ACTION;
	switch (ret) {
#if defined(CONFIG_SECCOMP_FILTER) || defined(CONFIG_SECCOMP_CAPSICUM)
	case SECCOMP_RET_ERRNO:
		/* Set the low-order 16-bits as a errno. */
		syscall_set_return_value(current, regs, -data, 0);
		goto skip;
	case SECCOMP_RET_TRAP:
		/* Show the handler the original registers. */
		syscall_rollback(current, regs);
		/* Let the filter pass back 16 bits of data. */
		seccomp_send_sigsys(this_syscall, data);
		goto skip;
	case SECCOMP_RET_TRACE:
		/* Skip these calls if there is no tracer. */
		if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
			syscall_set_return_value(current, regs, -ENOSYS, 0);
			goto skip;
		}
		/* Allow the BPF to provide the event message */
		ptrace_event(PTRACE_EVENT_SECCOMP, data);
		/*
		 * The delivery of a fatal signal during event
		 * notification may silently skip tracer notification.
		 * Terminating the task now avoids executing a system
		 * call that may not be intended.
		 */
		if (fatal_signal_pending(current))
			break;
		if (syscall_get_nr(current, regs) < 0)
			goto skip;  /* Explicit request to skip. */
		return 0;
#endif
	case SECCOMP_RET_ALLOW:
		return 0;
	case SECCOMP_RET_KILL:
	default:
		break;
	}
	if (!exit_sig)
		exit_sig = SIGSYS;

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	audit_seccomp(this_syscall, exit_sig, ret);
	do_exit(exit_sig);
#if defined(CONFIG_SECCOMP_FILTER) || defined(CONFIG_SECCOMP_CAPSICUM)
skip:
#endif
	audit_seccomp(this_syscall, exit_sig, ret);
	return -1;
}

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

/**
 * seccomp_set_mode: internal function for setting seccomp mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * This function may be called repeatedly with a @seccomp_mode of
 * SECCOMP_MODE_FILTER to install additional filters.  Every filter
 * successfully installed will be evaluated (in reverse order) for each system
 * call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode(unsigned long seccomp_mode, char __user *filter)
{
	struct seccomp_filter *prepared = NULL;
	unsigned long irqflags;
	long ret = -EINVAL;

#ifdef CONFIG_SECCOMP_FILTER
	/* Prepare the new filter outside of the seccomp lock. */
	if (seccomp_mode & SECCOMP_MODE_FILTER) {
		prepared = seccomp_prepare_user_filter(filter);
		if (IS_ERR(prepared))
			return PTR_ERR(prepared);
	}
#endif
#ifdef CONFIG_SECCOMP_CAPSICUM
	/*
	 * Check for no-new-privs outside of the seccomp lock (as
	 * it may alloc credentials under the covers).
	 */
	if (seccomp_mode & SECCOMP_MODE_CAPSICUM) {
		if (!seccomp_has_no_new_privs())
			return -EACCES;
	}
#endif

	seccomp_lock(current, &irqflags);

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		ret = 0;
#ifdef TIF_NOTSC
		disable_TSC();
#endif
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER:
		ret = _seccomp_attach_filter(prepared);
		if (ret)
			goto out;
		/* Do not free the successfully attached filter. */
		prepared = NULL;
		break;
#endif
#ifdef CONFIG_SECCOMP_CAPSICUM
	case SECCOMP_MODE_CAPSICUM:
		ret = 0;
		break;
#endif
	default:
		goto out;
	}

	current->seccomp.mode |= seccomp_mode;
	set_thread_flag(TIF_SECCOMP);
out:
	seccomp_unlock(current, irqflags);
	kfree(prepared);
	return ret;
}

/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use; only a single bit should be set
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * Returns 0 on success or -EINVAL on failure.
 */
long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	long ret;

	ret = seccomp_set_mode(seccomp_mode, filter);
	return ret;
}
