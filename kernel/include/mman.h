/**
 * \file mman.h
 *  License details are found in the file LICENSE.
 * \brief
 *  memory management declarations
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#ifndef HEADER_MMAN_H
#define HEADER_MMAN_H

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
#define	MAP_32BIT	0x40
#define	MAP_GROWSDOWN	0x0100
#define	MAP_DENYWRITE	0x0800
#define	MAP_EXECUTABLE	0x1000
#define	MAP_LOCKED	0x2000
#define	MAP_NORESERVE	0x4000
#define	MAP_POPULATE	0x8000
#define	MAP_NONBLOCK	0x00010000
#define	MAP_STACK	0x00020000
#define	MAP_HUGETLB	0x00040000

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
#define	MADV_HWPOISON		100
#define	MADV_SOFT_OFFLINE	101

/*
 * for mremap()
 */
#define	MREMAP_MAYMOVE	0x01
#define	MREMAP_FIXED	0x02

#endif /* HEADER_MMAN_H */
