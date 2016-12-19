/**
 * \file pager.h
 *  License details are found in the file LICENSE.
 * \brief
 *  file back-ended pager declarations
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */
#ifndef HEADER_PAGER_H
#define HEADER_PAGER_H

#include <ihk/types.h>

enum pager_op {
	PAGER_REQ_CREATE =	0x0001,
	PAGER_REQ_RELEASE =	0x0002,
	PAGER_REQ_READ =	0x0003,
	PAGER_REQ_WRITE =	0x0004,
	PAGER_REQ_MAP =		0x0005,
	PAGER_REQ_PFN =		0x0006,
	PAGER_REQ_UNMAP =	0x0007,
};

/*
 * int pager_req_create(int fd, int flags, int prot, uintptr_t result_rpa);
 */
struct pager_create_result {
	uintptr_t	handle;
	int		maxprot;
	uint32_t flags;
	size_t size;
};

/*
 * int pager_req_release(uintptr_t handle);
 */
/*
 * int pager_req_read(uintptr_t handle, off_t off, size_t size, uintptr_t buf_rpa);
 */
/*
 */
struct pager_map_result {
	uintptr_t	handle;
	int		maxprot;
	int8_t		padding[4];
};

/* for pager_req_pfn() */
#define	PFN_VALID	((uintptr_t)1 << 63)
#define	PFN_PRESENT	((uintptr_t)1 << 0)
#define	PFN_PFN		((((uintptr_t)1 << 56) - 1) & ~(PAGE_SIZE - 1))

#endif /* HEADER_PAGER_H */
