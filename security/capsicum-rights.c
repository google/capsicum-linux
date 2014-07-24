/*-
 * Copyright (c) 2013 FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdarg.h>
#include <linux/capsicum.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/bug.h>

#include "capsicum-rights.h"

#ifdef CONFIG_SECURITY_CAPSICUM
#define CAPARSIZE_MIN	(CAP_RIGHTS_VERSION_00 + 2)
#define CAPARSIZE_MAX	(CAP_RIGHTS_VERSION + 2)

/*
 * -1 indicates invalid index value, otherwise log2(v), ie.:
 * 0x001 -> 0, 0x002 -> 1, 0x004 -> 2, 0x008 -> 3, 0x010 -> 4, rest -> -1
 */
static const int bit2idx[] = {
	-1, 0, 1, -1, 2, -1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1,
	4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static inline int right_to_index(__u64 right)
{
	return bit2idx[CAPIDXBIT(right)];
}

static inline bool has_right(const struct capsicum_rights *rights, u64 right)
{
	int idx = right_to_index(right);

	return (rights->primary.cr_rights[idx] & right) == right;
}

struct capsicum_rights *
cap_rights_vset(struct capsicum_rights *rights, va_list ap)
{
	u64 right;
	int i, n;

	n = CAPARSIZE(&rights->primary);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	while (true) {
		right = va_arg(ap, u64);
		if (right == 0)
			break;
		BUG_ON(CAPRVER(right) != 0);
		i = right_to_index(right);
		BUG_ON(i < 0 || i >= n);
		BUG_ON(CAPIDXBIT(rights->primary.cr_rights[i]) !=
		       CAPIDXBIT(right));
		rights->primary.cr_rights[i] |= right;
	}
	return rights;
}
EXPORT_SYMBOL(cap_rights_vset);

struct capsicum_rights *
cap_rights_vinit(struct capsicum_rights *rights, va_list ap)
{
	CAP_SET_NONE(&rights->primary);
	rights->nioctls = 0;
	rights->ioctls = NULL;
	rights->fcntls = 0;
	cap_rights_vset(rights, ap);
	return rights;
}
EXPORT_SYMBOL(cap_rights_vinit);

bool cap_rights_regularize(struct capsicum_rights *rights)
{
	bool changed = false;

	if (!has_right(rights, CAP_FCNTL) && rights->fcntls != 0x00) {
		changed = true;
		rights->fcntls = 0x00;
	}
	if (!has_right(rights, CAP_IOCTL) && (rights->nioctls != 0)) {
		changed = true;
		kfree(rights->ioctls);
		rights->nioctls = 0;
		rights->ioctls = NULL;
	}
	return changed;
}

struct capsicum_rights *_cap_rights_init(struct capsicum_rights *rights, ...)
{
	va_list ap;

	va_start(ap, rights);
	cap_rights_vinit(rights, ap);
	va_end(ap);
	return rights;
}
EXPORT_SYMBOL(_cap_rights_init);

struct capsicum_rights *_cap_rights_set(struct capsicum_rights *rights, ...)
{
	va_list ap;

	va_start(ap, rights);
	cap_rights_vset(rights, ap);
	va_end(ap);
	return rights;
}
EXPORT_SYMBOL(_cap_rights_set);

struct capsicum_rights *cap_rights_set_all(struct capsicum_rights *rights)
{
	CAP_SET_ALL(&rights->primary);
	rights->nioctls = -1;
	rights->ioctls = NULL;
	rights->fcntls = CAP_FCNTL_ALL;
	return rights;
}
EXPORT_SYMBOL(cap_rights_set_all);

static bool cap_rights_ioctls_contains(const struct capsicum_rights *big,
				       const struct capsicum_rights *little)
{
	int i, j;

	if (big->nioctls == -1)
		return true;
	if (big->nioctls < little->nioctls)
		return false;
	for (i = 0; i < little->nioctls; i++) {
		for (j = 0; j < big->nioctls; j++) {
			if (little->ioctls[i] == big->ioctls[j])
				break;
		}
		if (j == big->nioctls)
			return false;
	}
	return true;
}

static bool cap_rights_primary_contains(const struct cap_rights *big,
					const struct cap_rights *little)
{
	unsigned int i, n;

	BUG_ON(CAPVER(big) != CAP_RIGHTS_VERSION_00);
	BUG_ON(CAPVER(little) != CAP_RIGHTS_VERSION_00);

	n = CAPARSIZE(big);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	for (i = 0; i < n; i++) {
		if ((big->cr_rights[i] & little->cr_rights[i]) !=
		    little->cr_rights[i]) {
			return false;
		}
	}
	return true;
}

bool cap_rights_contains(const struct capsicum_rights *big,
			const struct capsicum_rights *little)
{
	return cap_rights_primary_contains(&big->primary,
					   &little->primary) &&
	       ((big->fcntls & little->fcntls) == little->fcntls) &&
	       cap_rights_ioctls_contains(big, little);
}

bool cap_rights_is_all(const struct capsicum_rights *rights)
{
	return CAP_IS_ALL(&rights->primary) &&
	       rights->fcntls == CAP_FCNTL_ALL &&
	       rights->nioctls == -1;
}
EXPORT_SYMBOL(cap_rights_is_all);

#endif  /* CONFIG_SECURITY_CAPSICUM */
