/* shm.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_ARCH_SHM_H
#define __HEADER_ARM64_ARCH_SHM_H

#include <arch-memory.h>

/* shmflg */
#define SHM_HUGE_SHIFT  26
#define SHM_HUGE_FIRST_BLOCK       (__PTL3_SHIFT << SHM_HUGE_SHIFT)
#define SHM_HUGE_FIRST_CONT_BLOCK  ((__PTL3_SHIFT + __PTL3_CONT_SHIFT) << SHM_HUGE_SHIFT)
#define SHM_HUGE_SECOND_BLOCK      (__PTL2_SHIFT << SHM_HUGE_SHIFT)
#define SHM_HUGE_SECOND_CONT_BLOCK ((__PTL2_SHIFT + __PTL2_CONT_SHIFT) << SHM_HUGE_SHIFT)
#define SHM_HUGE_THIRD_CONT_BLOCK  ((__PTL1_SHIFT + __PTL1_CONT_SHIFT) << SHM_HUGE_SHIFT)

struct ipc_perm {
	key_t		key;
	uid_t		uid;
	gid_t		gid;
	uid_t		cuid;
	gid_t		cgid;
	uint16_t	mode;
	uint8_t		padding[2];
	uint16_t	seq;
	uint8_t		padding2[22];
};

struct shmid_ds {
	struct ipc_perm	shm_perm;
	size_t		shm_segsz;
	time_t		shm_atime;
	time_t		shm_dtime;
	time_t		shm_ctime;
	pid_t		shm_cpid;
	pid_t		shm_lpid;
	uint64_t	shm_nattch;
	uint8_t		padding[12];
	int		init_pgshift;
};

#endif /* __HEADER_ARM64_ARCH_SHM_H */
