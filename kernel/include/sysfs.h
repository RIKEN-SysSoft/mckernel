/**
 * \file sysfs.h
 *  License details are found in the file LICENSE.
 * \brief
 *  sysfs framework API definitions
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#ifndef MCKERNEL_SYSFS_H
#define MCKERNEL_SYSFS_H

#define SYSFS_PATH_MAX 1024

/* for sysfs_unlinkf() */
#define SYSFS_UNLINK_KEEP_ANCESTOR      0x01


struct sysfs_ops {
	ssize_t (*show)(struct sysfs_ops *ops, void *instance, void *buf,
			size_t bufsize);
	ssize_t (*store)(struct sysfs_ops *ops, void *instance, void *buf,
			size_t bufsize);
	void (*release)(struct sysfs_ops *ops, void *instance);
};

struct sysfs_handle {
	long handle;
};
typedef struct sysfs_handle sysfs_handle_t;

struct sysfs_bitmap_param {
	int nbits;
	int padding;
	void *ptr;
};

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

static inline int is_special_sysfs_ops(void *ops)
{
	return (((long)SYSFS_SPECIAL_OPS_MIN <= (long)ops)
			&& ((long)ops <= (long)SYSFS_SPECIAL_OPS_MAX));
}

extern int sysfs_createf(struct sysfs_ops *ops, void *instance, int mode,
		const char *fmt, ...);
extern int sysfs_mkdirf(sysfs_handle_t *dirhp, const char *fmt, ...);
extern int sysfs_symlinkf(sysfs_handle_t targeth, const char *fmt, ...);
extern int sysfs_lookupf(sysfs_handle_t *objhp, const char *fmt, ...);
extern int sysfs_unlinkf(int flags, const char *fmt, ...);

extern void sysfs_init(void);
struct ihk_ikc_channel_desc;
extern void sysfss_packet_handler(struct ihk_ikc_channel_desc *ch, int msg,
		int error, long arg1, long arg2, long arg3);

#endif /* MCKERNEL_SYSFS_H */
