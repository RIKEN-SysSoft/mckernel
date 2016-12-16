/**
 * \file mc_xpmem.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Cross Partition Memory (XPMEM) structures and macros.
 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 */
/*
 * HISTORY
 */

#ifndef _MC_XPMEM_H
#define _MC_XPMEM_H

#ifndef __KERNEL__
#include <sys/types.h>
#endif

/*
 * _IOC definitions for McKernel
 */
#define _IOC_NRBITS	8
#define _IOC_TYPEBITS	8

#define _IOC_SIZEBITS	14

#define _IOC_DIRBITS	2

#define _IOC_NRSHIFT	0
#define _IOC_TYPESHIFT	(_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT	(_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT	(_IOC_SIZESHIFT+_IOC_SIZEBITS)

#define _IOC_NONE	0U

#define _IOC(dir,type,nr,size) \
	(((dir)  << _IOC_DIRSHIFT) | \
	 ((type) << _IOC_TYPESHIFT) | \
	 ((nr)   << _IOC_NRSHIFT) | \
	 ((size) << _IOC_SIZESHIFT))

#define _IO(type,nr) _IOC(_IOC_NONE,(type),(nr),0)

/*
 * basic argument type definitions for McKernel
 */
typedef uint64_t u64;
typedef uint64_t __u64;
typedef int64_t __s64;

/*
 * basic argument type definitions
 */
typedef __s64 xpmem_segid_t;	/* segid returned from xpmem_make() */
typedef __s64 xpmem_apid_t;	/* apid returned from xpmem_get() */

struct xpmem_addr {
	xpmem_apid_t apid;	/* apid that represents memory */
	off_t offset;		/* offset into apid's memory */
};

#define XPMEM_MAXADDR_SIZE	(size_t)(-1L)

/*
 * path to XPMEM device
 */
#define XPMEM_DEV_PATH  "/dev/xpmem"

/*
 * The following are the possible XPMEM related errors.
 */
#define XPMEM_ERRNO_NOPROC	2004	/* unknown thread due to fork() */

/*
 * flags for segment permissions
 */
#define XPMEM_RDONLY	0x1
#define XPMEM_RDWR	0x2

/*
 * Valid permit_type values for xpmem_make().
 */
#define XPMEM_PERMIT_MODE	0x1

/*
 * ioctl() commands used to interface to the kernel module.
 */
#define XPMEM_IOC_MAGIC		'x'
#define XPMEM_CMD_VERSION	_IO(XPMEM_IOC_MAGIC, 0)
#define XPMEM_CMD_MAKE		_IO(XPMEM_IOC_MAGIC, 1)
#define XPMEM_CMD_REMOVE	_IO(XPMEM_IOC_MAGIC, 2)
#define XPMEM_CMD_GET		_IO(XPMEM_IOC_MAGIC, 3)
#define XPMEM_CMD_RELEASE	_IO(XPMEM_IOC_MAGIC, 4)
#define XPMEM_CMD_ATTACH	_IO(XPMEM_IOC_MAGIC, 5)
#define XPMEM_CMD_DETACH	_IO(XPMEM_IOC_MAGIC, 6)

/*
 * Structures used with the preceding ioctl() commands to pass data.
 */
struct xpmem_cmd_make {
	__u64 vaddr;
	size_t size;
	int permit_type;
	__u64 permit_value;
	xpmem_segid_t segid;	/* returned on success */
};

struct xpmem_cmd_remove {
	xpmem_segid_t segid;
};

struct xpmem_cmd_get {
	xpmem_segid_t segid;
	int flags;
	int permit_type;
	__u64 permit_value;
	xpmem_apid_t apid;	/* returned on success */
};

struct xpmem_cmd_release {
	xpmem_apid_t apid;
};

struct xpmem_cmd_attach {
	xpmem_apid_t apid;
	off_t offset;
	size_t size;
	__u64 vaddr;
	int fd;
	int flags;
};

struct xpmem_cmd_detach {
	__u64 vaddr;
};

#ifndef __KERNEL__
extern int xpmem_version(void);
extern xpmem_segid_t xpmem_make(void *, size_t, int, void *);
extern int xpmem_remove(xpmem_segid_t);
extern xpmem_apid_t xpmem_get(xpmem_segid_t, int, int, void *);
extern int xpmem_release(xpmem_apid_t);
extern void *xpmem_attach(struct xpmem_addr, size_t, void *);
extern int xpmem_detach(void *);
#endif

#endif /* _MC_XPMEM_H */
