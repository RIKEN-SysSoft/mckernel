/**
 * \file shm.h
 *  License details are found in the file LICENSE.
 * \brief
 *  header file for System V shared memory
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef HEADER_ARCH_SHM_H
#define HEADER_ARCH_SHM_H

/* shmflg */
#define SHM_HUGE_SHIFT  26
#define SHM_HUGE_2MB    (21 << SHM_HUGE_SHIFT)
#define SHM_HUGE_1GB    (30 << SHM_HUGE_SHIFT)

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

#endif /* HEADER_ARCH_SHM_H */
