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

#endif /* HEADER_MMAN_H */
