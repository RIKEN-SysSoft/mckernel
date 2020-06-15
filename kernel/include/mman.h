/**
 * \file mman.h
 *  License details are found in the file LICENSE.
 * \brief
 *  memory management declarations
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef HEADER_MMAN_H
#define HEADER_MMAN_H

#include <arch/mman.h>

/*
 * memory protection
 */
#define	PROT_NONE	0
#define	PROT_READ	0x01
#define	PROT_WRITE	0x02
#define	PROT_EXEC	0x04

/* for mprotect */
#define	PROT_GROWSDOWN	0x01000000
#define	PROT_GROWSUP	0x02000000

/*
 * mapping flags
 */
#define	MAP_SHARED	0x01
#define	MAP_PRIVATE	0x02
#define	MAP_FIXED	0x10
#define	MAP_ANONYMOUS	0x20

/*
 * memory advice
 */
#define	MADV_NORMAL		0
#define	MADV_RANDOM		1
#define	MADV_SEQUENTIAL		2
#define	MADV_WILLNEED		3
#define	MADV_DONTNEED		4
#define	MADV_REMOVE		9
#define	MADV_DONTFORK		10
#define	MADV_DOFORK		11
#define	MADV_MERGEABLE		12
#define	MADV_UNMERGEABLE	13
#define	MADV_HUGEPAGE		14
#define	MADV_NOHUGEPAGE		15
#define	MADV_DONTDUMP		16
#define	MADV_DODUMP		17
#define	MADV_WIPEONFORK		18 /* Zero memory on fork, child only */
#define	MADV_KEEPONFORK		19 /* Undo MADV_WIPEONFORK */
#define	MADV_HWPOISON		100
#define	MADV_SOFT_OFFLINE	101

/*
 * for mremap()
 */
#define	MREMAP_MAYMOVE	0x01
#define	MREMAP_FIXED	0x02

/*
 * for msync()
 */
#define	MS_ASYNC	0x01
#define	MS_INVALIDATE	0x02
#define	MS_SYNC		0x04

/* include/uapi/linux/mman.h */
#define OVERCOMMIT_GUESS		0
#define OVERCOMMIT_ALWAYS		1
#define OVERCOMMIT_NEVER		2

extern int sysctl_overcommit_memory;

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#endif /* HEADER_MMAN_H */
