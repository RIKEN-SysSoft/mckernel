/**
 * \file mman.h
 *  License details are found in the file LICENSE.
 * \brief
 *  memory management declarations
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef HEADER_ARCH_MMAN_H
#define HEADER_ARCH_MMAN_H

/*
 * mapping flags
 */
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

#define MAP_HUGE_SHIFT  26
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)

/*
 * for mlockall()
 */
#define	MCL_CURRENT	0x01
#define	MCL_FUTURE	0x02

#endif /* HEADER_ARCH_MMAN_H */
