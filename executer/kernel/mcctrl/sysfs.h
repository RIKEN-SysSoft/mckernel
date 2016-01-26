/**
 * \file sysfs.h
 *  License details are found in the file LICENSE.
 * \brief
 *  sysfs framework API definitions
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2016  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef MCCTRL_SYSFS_H
#define MCCTRL_SYSFS_H

#define SYSFS_PATH_MAX 1024

/* for sysfs_unlinkf() */
#define SYSFS_UNLINK_KEEP_ANCESTOR      0x01


struct sysfsm_ops {
	ssize_t (*show)(struct sysfsm_ops *ops, void *instance, void *buf,
			size_t bufsize);
	ssize_t (*store)(struct sysfsm_ops *ops, void *instance,
			const void *buf, size_t bufsize);
	void (*release)(struct sysfsm_ops *ops, void *instance);
};

struct sysfs_handle {
	long handle;
};
typedef struct sysfs_handle sysfs_handle_t;


extern int sysfsm_createf(ihk_os_t os, struct sysfsm_ops *ops, void *instance,
		int mode, const char *fmt, ...);
extern int sysfsm_mkdirf(ihk_os_t os, sysfs_handle_t *dirhp,
		const char *fmt, ...);
extern int sysfsm_symlinkf(ihk_os_t os, sysfs_handle_t targeth,
		const char *fmt, ...);
extern int sysfsm_lookupf(ihk_os_t os, sysfs_handle_t *objhp,
		const char *fmt, ...);
extern int sysfsm_unlinkf(ihk_os_t os, int flags, const char *fmt, ...);

extern void sysfsm_cleanup(ihk_os_t os);
extern void sysfsm_packet_handler(void *os, int msg, int err, long arg1,
		long arg2);

#endif /* MCCTRL_SYSFS_H */
