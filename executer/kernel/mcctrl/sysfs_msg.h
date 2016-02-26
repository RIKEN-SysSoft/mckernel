/**
 * \file sysfs_msg.h
 *  License details are found in the file LICENSE.
 * \brief
 *   message declarations for sysfs framework
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef MCKERNEL_SYSFS_MSG_H
#define MCKERNEL_SYSFS_MSG_H

#define SYSFS_PATH_MAX 1024

struct sysfs_req_create_param {
	int mode;
	int error;
	long client_ops;
	long client_instance;
	char path[SYSFS_PATH_MAX];
	int padding;
	int busy;
}; /* struct sysfs_req_create_param */

#define SYSFS_SPECIAL_OPS_MIN ((void *)1)
#define SYSFS_SPECIAL_OPS_MAX ((void *)1000)

#define SYSFS_SNOOPING_OPS_d32 ((void *)1)
#define SYSFS_SNOOPING_OPS_d64 ((void *)2)
#define SYSFS_SNOOPING_OPS_u32 ((void *)3)
#define SYSFS_SNOOPING_OPS_u64 ((void *)4)
#define SYSFS_SNOOPING_OPS_s ((void *)5)
#define SYSFS_SNOOPING_OPS_pbl ((void *)6)
#define SYSFS_SNOOPING_OPS_pb ((void *)7)
#define SYSFS_SNOOPING_OPS_u32K ((void *)8)

struct sysfs_req_mkdir_param {
	int error;
	int padding;
	long handle;
	char path[SYSFS_PATH_MAX];
	int padding2;
	int busy;
}; /* struct sysfs_req_mkdir_param */

struct sysfs_req_symlink_param {
	int error;
	int padding;
	long target;
	char path[SYSFS_PATH_MAX];
	int padding2;
	int busy;
}; /* struct sysfs_req_symlink_param */

struct sysfs_req_lookup_param {
	int error;
	int padding;
	long handle;
	char path[SYSFS_PATH_MAX];
	int padding2;
	int busy;
}; /* struct sysfs_req_lookup_param */

/* for sysfs_req_unlink_param.flags */
#define SYSFS_UNLINK_KEEP_ANCESTOR      0x01

struct sysfs_req_unlink_param {
	int flags;
	int error;
	char path[SYSFS_PATH_MAX];
	int padding;
	int busy;
}; /* struct sysfs_req_unlink_param */

struct sysfs_req_setup_param {
	int error;
	int padding;
	long buf_rpa;
	long bufsize;
	char padding3[SYSFS_PATH_MAX];
	int padding2;
	int busy;
}; /* struct sysfs_req_setup_param */

#endif /* MCKERNEL_SYSFS_MSG_H */
