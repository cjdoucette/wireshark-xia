/* packet-xip-dag-userland.h
 * Utility routines and definitions for XIP packet dissection.
 * Copyright 2012, Cody Doucette <doucette@bu.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef __KERNEL__

#include <linux/ctype.h>
#include <linux/spinlock.h>
#include <linux/export.h>

#define mymalloc(n)	kmalloc(n, GFP_ATOMIC)
#define myfree(p)	kfree(p)

#else /* Userland */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <asm-generic/errno-base.h>

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos &&							 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
	     pos = pos->next)
#define hlist_for_each_entry_rcu	hlist_for_each_entry

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}
#define hlist_add_head_rcu	hlist_add_head

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

#define LIST_POISON1	NULL
#define LIST_POISON2	NULL
static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}
#define hlist_del_rcu		hlist_del

#define mymalloc(n)	malloc(n)
#define myfree(p)	free(p)

#define BUG_ON(b)	assert(!(b))

/* Force a compilation error if a constant expression is not a power of 2 */
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))

#define EXPORT_SYMBOL(x)

#define spin_lock(x)
#define spin_unlock(x)

static inline void rcu_read_lock(void)		{ }
static inline void rcu_read_unlock(void)	{ }
static inline void synchronize_rcu(void)	{ }

#define likely(b) (b)
#define unlikely(b) (b)

#endif /* __KERNEL__ */
