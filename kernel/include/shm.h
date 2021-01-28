/**
 * \file shm.h
 *  License details are found in the file LICENSE.
 * \brief
 *  header file for System V shared memory
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014 - 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef HEADER_SHM_H
#define HEADER_SHM_H

#include <list.h>
#include <memobj.h>
#include <arch/shm.h>

enum {
	/* for key_t */
	IPC_PRIVATE	= 0,

	/* for shmflg */
	IPC_CREAT	= 01000,
	IPC_EXCL	= 02000,

	SHM_HUGETLB	= 04000,
	SHM_RDONLY	= 010000,
	SHM_RND		= 020000,
	SHM_REMAP	= 040000,
	SHM_EXEC	= 0100000,

	/* for shm_mode */
	SHM_DEST	= 01000, /* Marked for destruction */
	SHM_LOCKED	= 02000,

	/* for cmd of shmctl() */
	IPC_RMID	= 0,
	IPC_SET		= 1,
	IPC_STAT	= 2,
	IPC_INFO	= 3,

	SHM_LOCK	= 11,
	SHM_UNLOCK	= 12,
	SHM_STAT	= 13,
	SHM_INFO	= 14,
};

struct shmlock_user;

struct shmobj {
	struct memobj		memobj;		/* must be first */
	int			index;
	int			pgshift;
	size_t			real_segsz;
	struct shmlock_user *	user;
	struct shmid_ds		ds;
	struct list_head	page_list;
	ihk_spinlock_t		page_list_lock;
	struct list_head	chain;		/* shmobj_list */
};

struct shminfo {
	uint64_t	shmmax;
	uint64_t	shmmin;
	uint64_t	shmmni;
	uint64_t	shmseg;
	uint64_t	shmall;
	uint8_t		padding[32];
};

struct shm_info {
	int32_t		used_ids;
	uint8_t		padding[4];
	uint64_t	shm_tot;
	uint64_t	shm_rss;
	uint64_t	shm_swp;
	uint64_t	swap_attempts;
	uint64_t	swap_successes;
};

struct shmlock_user {
	uid_t ruid;
	int padding;
	size_t locked;

	struct list_head chain;
};

extern ihk_spinlock_t shmlock_users_lock_body;

static inline void shmlock_users_lock(void)
{
	ihk_mc_spinlock_lock_noirq(&shmlock_users_lock_body);
	return;
}

static inline void shmlock_users_unlock(void)
{
	ihk_mc_spinlock_unlock_noirq(&shmlock_users_lock_body);
	return;
}

void shmobj_list_lock(void);
void shmobj_list_unlock(void);
int shmobj_create_indexed(struct shmid_ds *ds, struct shmobj **objp);
void shmlock_user_free(struct shmlock_user *user);
int shmlock_user_get(uid_t ruid, struct shmlock_user **userp);
struct shmobj *to_shmobj(struct memobj *memobj);

#endif /* HEADER_SHM_H */
