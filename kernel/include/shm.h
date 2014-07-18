/**
 * \file shm.h
 *  License details are found in the file LICENSE.
 * \brief
 *  header file for System V shared memory
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com>
 */
/*
 * HISTORY:
 */

#ifndef HEADER_SHM_H
#define HEADER_SHM_H

/* begin types.h */
typedef int32_t key_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef int64_t time_t;
typedef int32_t pid_t;
/* end types.h */

typedef uint64_t shmatt_t;

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
	shmatt_t	shm_nattch;
	uint8_t		padding[16];
};

#endif /* HEADER_SHM_H */
