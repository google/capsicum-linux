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
#include <asm/bug.h>

#ifdef CONFIG_SECURITY_CAPSICUM
#define CAPARSIZE_MIN	(CAP_RIGHTS_VERSION_00 + 2)
#define CAPARSIZE_MAX	(CAP_RIGHTS_VERSION + 2)

/* -1 indicates invalid index value, otherwise log2(v), ie.: */
/* 0x001 -> 0 */
/* 0x002 -> 1 */
/* 0x004 -> 2 */
/* 0x008 -> 3 */
/* 0x010 -> 4 */
static const int bit2idx[] = {
	-1, 0, 1, -1, 2, -1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1,
	4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static inline int right_to_index(__u64 right)
{
	int idx = CAPIDXBIT(right);
	return (bit2idx[idx]);
}

static void cap_rights_vset(struct cap_rights *rights, va_list ap)
{
	u64 right;
	int i, n;

	n = CAPARSIZE(rights);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	while (true) {
		right = va_arg(ap, u64);
		if (right == 0)
			break;
		BUG_ON(CAPRVER(right) != 0);
		i = right_to_index(right);
		BUG_ON(i < 0 || i >= n);
		BUG_ON(CAPIDXBIT(rights->cr_rights[i]) != CAPIDXBIT(right));
		rights->cr_rights[i] |= right;
	}
}

static void cap_rights_vclear(struct cap_rights *rights, va_list ap)
{
	u64 right;
	int i, n;

	n = CAPARSIZE(rights);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	while (true) {
		right = va_arg(ap, u64);
		if (right == 0)
			break;
		BUG_ON(CAPRVER(right) != 0);
		i = right_to_index(right);
		BUG_ON(i < 0 || i >= n);
		BUG_ON(CAPIDXBIT(rights->cr_rights[i]) != CAPIDXBIT(right));
		rights->cr_rights[i] &= ~(right & 0x01FFFFFFFFFFFFFFULL);
	}
}

static bool cap_rights_is_vset(const struct cap_rights *rights, va_list ap)
{
	u64 right;
	int i, n;

	n = CAPARSIZE(rights);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	while (true) {
		right = va_arg(ap, u64);
		if (right == 0)
			break;
		BUG_ON(CAPRVER(right) != 0);
		i = right_to_index(right);
		BUG_ON(i < 0 || i >= n);
		BUG_ON(CAPIDXBIT(rights->cr_rights[i]) != CAPIDXBIT(right));
		if ((rights->cr_rights[i] & right) != right)
			return false;
	}
	return true;
}

struct cap_rights *_cap_rights_init(struct cap_rights *rights, ...)
{
	va_list ap;
	CAP_NONE(rights);
	va_start(ap, rights);
	cap_rights_vset(rights, ap);
	va_end(ap);

	return rights;
}
EXPORT_SYMBOL(_cap_rights_init);

struct cap_rights *_cap_rights_set(struct cap_rights *rights, ...)
{
	va_list ap;
	BUG_ON(CAPVER(rights) != CAP_RIGHTS_VERSION_00);
	va_start(ap, rights);
	cap_rights_vset(rights, ap);
	va_end(ap);
	return rights;
}
EXPORT_SYMBOL(_cap_rights_set);

struct cap_rights *_cap_rights_clear(struct cap_rights *rights, ...)
{
	va_list ap;
	BUG_ON(CAPVER(rights) != CAP_RIGHTS_VERSION_00);
	va_start(ap, rights);
	cap_rights_vclear(rights, ap);
	va_end(ap);
	return rights;
}
EXPORT_SYMBOL(_cap_rights_clear);

bool _cap_rights_is_set(const struct cap_rights *rights, ...)
{
	va_list ap;
	bool ret;
	BUG_ON(CAPVER(rights) != CAP_RIGHTS_VERSION_00);
	va_start(ap, rights);
	ret = cap_rights_is_vset(rights, ap);
	va_end(ap);
	return ret;
}

bool cap_rights_is_valid(const struct cap_rights *rights)
{
	struct cap_rights allrights;
	int i, j;

	if (CAPVER(rights) != CAP_RIGHTS_VERSION_00)
		return false;
	if (CAPARSIZE(rights) < CAPARSIZE_MIN ||
	    CAPARSIZE(rights) > CAPARSIZE_MAX) {
		return false;
	}
	CAP_ALL(&allrights);
	if (!cap_rights_contains(&allrights, rights))
		return false;
	for (i = 0; i < CAPARSIZE(rights); i++) {
		j = right_to_index(rights->cr_rights[i]);
		if (i != j)
			return false;
		if (i > 0) {
			if (CAPRVER(rights->cr_rights[i]) != 0)
				return false;
		}
	}
	return true;
}

struct cap_rights *cap_rights_merge(struct cap_rights *dst,
				    const struct cap_rights *src)
{
	unsigned int i, n;

	BUG_ON(CAPVER(dst) != CAP_RIGHTS_VERSION_00);
	BUG_ON(CAPVER(src) != CAP_RIGHTS_VERSION_00);
	BUG_ON(!cap_rights_is_valid(src));
	BUG_ON(!cap_rights_is_valid(dst));

	n = CAPARSIZE(dst);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	for (i = 0; i < n; i++)
		dst->cr_rights[i] |= src->cr_rights[i];

	BUG_ON(!cap_rights_is_valid(dst));
	return dst;
}

struct cap_rights *cap_rights_remove(struct cap_rights *dst,
				     const struct cap_rights *src)
{
	unsigned int i, n;

	BUG_ON(CAPVER(dst) != CAP_RIGHTS_VERSION_00);
	BUG_ON(CAPVER(src) != CAP_RIGHTS_VERSION_00);
	BUG_ON(!cap_rights_is_valid(src));
	BUG_ON(!cap_rights_is_valid(dst));

	n = CAPARSIZE(dst);
	BUG_ON(n < CAPARSIZE_MIN || n > CAPARSIZE_MAX);

	for (i = 0; i < n; i++) {
		dst->cr_rights[i] &= ~(src->cr_rights[i] & 0x01FFFFFFFFFFFFFFULL);
	}

	BUG_ON(!cap_rights_is_valid(dst));
	return dst;
}

bool cap_rights_contains(const struct cap_rights *big,
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

#endif
