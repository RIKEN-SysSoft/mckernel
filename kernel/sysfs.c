/**
 * \file sysfs.c
 *  License details are found in the file LICENSE.
 * \brief
 *  sysfs framework, IHK-Slave side
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#include <ihk/mm.h>
#include <ihk/types.h>
#include <ikc/queue.h>
#include <cls.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <page.h>
#include <string.h>
#include <stdarg.h>
#include <arch/cpu.h>
#include <sysfs.h>
#include <sysfs_msg.h>
#include <vsprintf.h>

#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) do { if (1) kprintf(__VA_ARGS__); } while (0)

static size_t sysfs_data_bufsize;
static void *sysfs_data_buf;

static int setup_special_create(struct sysfs_req_create_param *param, struct sysfs_bitmap_param *pbp)
{
	void *cinstance = (void *)param->client_instance;

	switch (param->client_ops) {
	case (long)SYSFS_SNOOPING_OPS_d32:
	case (long)SYSFS_SNOOPING_OPS_d64:
	case (long)SYSFS_SNOOPING_OPS_u32:
	case (long)SYSFS_SNOOPING_OPS_u64:
	case (long)SYSFS_SNOOPING_OPS_u32K:
		param->client_instance = virt_to_phys(cinstance);
		return 0;

	case (long)SYSFS_SNOOPING_OPS_s:
		pbp->nbits = 8 * (strlen(cinstance) + 1);
		pbp->ptr = (void *)virt_to_phys(cinstance);
		param->client_instance = virt_to_phys(pbp);
		return 0;

	case (long)SYSFS_SNOOPING_OPS_pbl:
	case (long)SYSFS_SNOOPING_OPS_pb:
		*pbp = *(struct sysfs_bitmap_param *)cinstance;
		pbp->ptr = (void *)virt_to_phys(pbp->ptr);
		param->client_instance = virt_to_phys(pbp);
		return 0;
	}

	ekprintf("setup_special_create:unknown ops %#lx\n", param->client_ops);
	return -EINVAL;
} /* setup_special_create() */

int
sysfs_createf(struct sysfs_ops *ops, void *instance, int mode,
		const char *fmt, ...)
{
	int error;
	va_list ap;
	ssize_t n;
	struct sysfs_req_create_param *param = NULL;
	struct ikc_scd_packet packet;
	struct sysfs_bitmap_param asbp;

	dkprintf("sysfs_createf(%p,%p,%#o,%s,...)\n",
			ops, instance, mode, fmt);

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_createf:allocate_pages failed. %d\n", error);
		goto out;
	}

	param->client_ops = (long)ops;
	param->client_instance = (long)instance;
	param->mode = mode;
	param->busy = 1;

	va_start(ap, fmt);
	n = vsnprintf(param->path, sizeof(param->path), fmt, ap);
	va_end(ap);
	if (n >= sizeof(param->path)) {
		error = -ENAMETOOLONG;
		ekprintf("sysfs_createf:vsnprintf failed. %d\n", error);
		goto out;
	}
	dkprintf("sysfs_createf:path %s\n", param->path);
	if (param->path[0] != '/') {
		error = -ENOENT;
		ekprintf("sysfs_createf:not an absolute path. %d\n", error);
		goto out;
	}

	if (is_special_sysfs_ops(ops)) {
		error = setup_special_create(param, &asbp);
		if (error) {
			ekprintf("sysfs_createf:setup_special_create failed. %d\n", error);
			goto out;
		}
	}

	packet.msg = SCD_MSG_SYSFS_REQ_CREATE;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_createf:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_createf:SCD_MSG_SYSFS_REQ_CREATE failed. %d\n",
				error);
		goto out;
	}

	error = 0;
out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_createf(%p,%p,%#o,%s,...): %d\n",
				ops, instance, mode, fmt, error);
	}
	dkprintf("sysfs_createf(%p,%p,%#o,%s,...): %d\n",
			ops, instance, mode, fmt, error);
	return error;
} /* sysfs_createf() */

int
sysfs_mkdirf(sysfs_handle_t *dirhp, const char *fmt, ...)
{
	int error;
	struct sysfs_req_mkdir_param *param = NULL;
	struct ikc_scd_packet packet;
	va_list ap;
	int n;

	dkprintf("sysfs_mkdirf(%p,%s,...)\n", dirhp, fmt);

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_mkdirf:allocate_pages failed. %d\n", error);
		goto out;
	}

	param->busy = 1;

	va_start(ap, fmt);
	n = vsnprintf(param->path, sizeof(param->path), fmt, ap);
	va_end(ap);
	if (n >= sizeof(param->path)) {
		error = -ENAMETOOLONG;
		ekprintf("sysfs_mkdirf:vsnprintf failed. %d\n", error);
		goto out;
	}
	dkprintf("sysfs_mkdirf:path %s\n", param->path);
	if (param->path[0] != '/') {
		error = -ENOENT;
		ekprintf("sysfs_mkdirf:not an absolute path. %d\n", error);
		goto out;
	}

	packet.msg = SCD_MSG_SYSFS_REQ_MKDIR;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_mkdirf:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_mkdirf:SCD_MSG_SYSFS_REQ_MKDIR failed. %d\n",
				error);
		goto out;
	}

	error = 0;
	if (dirhp) {
		dirhp->handle = param->handle;
	}

out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_mkdirf(%p,%s,...): %d\n", dirhp, fmt, error);
	}
	dkprintf("sysfs_mkdirf(%p,%s,...): %d %#lx\n", dirhp, fmt, error,
			(dirhp)?dirhp->handle:0);
	return error;
} /* sysfs_mkdirf() */

int
sysfs_symlinkf(sysfs_handle_t targeth, const char *fmt, ...)
{
	int error;
	struct sysfs_req_symlink_param *param = NULL;
	struct ikc_scd_packet packet;
	va_list ap;
	int n;

	dkprintf("sysfs_symlinkf(%#lx,%s,...)\n", targeth.handle, fmt);

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_symlinkf:allocate_pages failed. %d\n", error);
		goto out;
	}

	param->target = targeth.handle;
	param->busy = 1;

	va_start(ap, fmt);
	n = vsnprintf(param->path, sizeof(param->path), fmt, ap);
	va_end(ap);
	if (n >= sizeof(param->path)) {
		error = -ENAMETOOLONG;
		ekprintf("sysfs_symlinkf:vsnprintf failed. %d\n", error);
		goto out;
	}
	dkprintf("sysfs_symlinkf:path %s\n", param->path);
	if (param->path[0] != '/') {
		error = -ENOENT;
		ekprintf("sysfs_symlinkf:not an absolute path. %d\n", error);
		goto out;
	}

	packet.msg = SCD_MSG_SYSFS_REQ_SYMLINK;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_symlinkf:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_symlinkf:"
				"SCD_MSG_SYSFS_REQ_SYMLINK failed. %d\n",
				error);
		goto out;
	}

	error = 0;
out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_symlinkf(%#lx,%s,...): %d\n",
				targeth.handle, fmt, error);
	}
	dkprintf("sysfs_symlinkf(%#lx,%s,...): %d\n",
			targeth.handle, fmt, error);
	return error;
} /* sysfs_symlinkf() */

int
sysfs_lookupf(sysfs_handle_t *objhp, const char *fmt, ...)
{
	int error;
	struct sysfs_req_lookup_param *param = NULL;
	struct ikc_scd_packet packet;
	va_list ap;
	int n;

	dkprintf("sysfs_lookupf(%p,%s,...)\n", objhp, fmt);

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_lookupf:allocate_pages failed. %d\n", error);
		goto out;
	}

	param->busy = 1;

	va_start(ap, fmt);
	n = vsnprintf(param->path, sizeof(param->path), fmt, ap);
	va_end(ap);
	if (n >= sizeof(param->path)) {
		error = -ENAMETOOLONG;
		ekprintf("sysfs_lookupf:vsnprintf failed. %d\n", error);
		goto out;
	}
	dkprintf("sysfs_lookupf:path %s\n", param->path);
	if (param->path[0] != '/') {
		error = -ENOENT;
		ekprintf("sysfs_lookupf:not an absolute path. %d\n", error);
		goto out;
	}

	packet.msg = SCD_MSG_SYSFS_REQ_LOOKUP;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_lookupf:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_lookupf:SCD_MSG_SYSFS_REQ_LOOKUP failed. %d\n",
				error);
		goto out;
	}

	error = 0;
	if (objhp) {
		objhp->handle = param->handle;
	}

out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_lookupf(%p,%s,...): %d\n", objhp, fmt, error);
	}
	dkprintf("sysfs_lookupf(%p,%s,...): %d %#lx\n", objhp, fmt, error,
			(objhp)?objhp->handle:0);
	return error;
} /* sysfs_lookupf() */

int
sysfs_unlinkf(int flags, const char *fmt, ...)
{
	int error;
	struct sysfs_req_unlink_param *param = NULL;
	struct ikc_scd_packet packet;
	va_list ap;
	int n;

	dkprintf("sysfs_unlinkf(%#x,%s,...)\n", flags, fmt);

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_unlinkf:allocate_pages failed. %d\n", error);
		goto out;
	}

	param->flags = flags;
	param->busy = 1;

	va_start(ap, fmt);
	n = vsnprintf(param->path, sizeof(param->path), fmt, ap);
	va_end(ap);
	if (n >= sizeof(param->path)) {
		error = -ENAMETOOLONG;
		ekprintf("sysfs_unlinkf:vsnprintf failed. %d\n", error);
		goto out;
	}
	dkprintf("sysfs_unlinkf:path %s\n", param->path);
	if (param->path[0] != '/') {
		error = -ENOENT;
		ekprintf("sysfs_unlinkf:not an absolute path. %d\n", error);
		goto out;
	}

	packet.msg = SCD_MSG_SYSFS_REQ_UNLINK;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_unlinkf:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_unlinkf:SCD_MSG_SYSFS_REQ_UNLINK failed. %d\n",
				error);
		goto out;
	}

	error = 0;
out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_unlinkf(%#x,%s,...): %d\n", flags, fmt, error);
	}
	dkprintf("sysfs_unlinkf(%#x,%s,...): %d\n", flags, fmt, error);
	return error;
} /* sysfs_unlinkf() */

static void
sysfss_req_show(long nodeh, struct sysfs_ops *ops, void *instance)
{
	int error;
	ssize_t ssize;
	struct ikc_scd_packet packet;

	dkprintf("sysfss_req_show(%#lx,%p,%p)\n", nodeh, ops, instance);

	ssize = -EIO;
	if (ops->show) {
		ssize = (*ops->show)(ops, instance, sysfs_data_buf,
				sysfs_data_bufsize);
		if (ssize < 0) {
			ekprintf("sysfss_req_show:->show failed. %ld\n",
					ssize);
			/* through */
		}
	}

	error = 0;
	if (ssize < 0) {
		error = ssize;
	}

	packet.msg = SCD_MSG_SYSFS_RESP_SHOW;
	packet.err = error;
	packet.sysfs_arg1 = nodeh;
	packet.sysfs_arg2 = ssize;

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfss_req_show:ihk_ikc_send failed. %d\n", error);
		/* through */
	}

	if (error || packet.err) {
		ekprintf("sysfss_req_show(%#lx,%p,%p): %d %d\n",
				nodeh, ops, instance, error, packet.err);
	}
	dkprintf("sysfss_req_show(%#lx,%p,%p): %d %d %ld\n",
			nodeh, ops, instance, error, packet.err, ssize);
	return;
} /* sysfss_req_show() */

static void
sysfss_req_store(long nodeh, struct sysfs_ops *ops, void *instance,
		size_t size)
{
	int error;
	ssize_t ssize;
	struct ikc_scd_packet packet;

	dkprintf("sysfss_req_store(%#lx,%p,%p,%d)\n",
			nodeh, ops, instance, size);

	ssize = -EIO;
	if (ops->store) {
		ssize = (*ops->store)(ops, instance, sysfs_data_buf, size);
		if (ssize < 0) {
			ekprintf("sysfss_req_store:->store failed. %ld\n",
					ssize);
			/* through */
		}
	}

	error = 0;
	if (ssize < 0) {
		error = ssize;
	}

	packet.msg = SCD_MSG_SYSFS_RESP_STORE;
	packet.err = error;
	packet.sysfs_arg1 = nodeh;
	packet.sysfs_arg2 = ssize;

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfss_req_store:ihk_ikc_send failed. %d\n", error);
		/* through */
	}

	if (error || packet.err) {
		ekprintf("sysfss_req_store(%#lx,%p,%p,%d): %d %d\n",
				nodeh, ops, instance, size, error, packet.err);
	}
	dkprintf("sysfss_req_store(%#lx,%p,%p,%d): %d %d %ld\n",
			nodeh, ops, instance, size, error, packet.err, ssize);
	return;
} /* sysfss_req_store() */

static void
sysfss_req_release(long nodeh, struct sysfs_ops *ops, void *instance)
{
	int error;
	struct ikc_scd_packet packet;

	dkprintf("sysfss_req_release(%#lx,%p,%p)\n", nodeh, ops, instance);

	if (ops->release) {
		(*ops->release)(ops, instance);
	}

	packet.msg = SCD_MSG_SYSFS_RESP_RELEASE;
	packet.err = 0;
	packet.sysfs_arg1 = nodeh;

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfss_req_release:ihk_ikc_send failed. %d\n",
				error);
		/* through */
	}

	if (error || packet.err) {
		ekprintf("sysfss_req_release(%#lx,%p,%p): %d %d\n",
				nodeh, ops, instance, error, packet.err);
	}
	dkprintf("sysfss_req_release(%#lx,%p,%p): %d %d\n",
			nodeh, ops, instance, error, packet.err);
	return;
} /* sysfss_req_release() */

void
sysfss_packet_handler(struct ihk_ikc_channel_desc *ch, int msg, int error,
		long arg1, long arg2, long arg3)
{
	switch (msg) {
	case SCD_MSG_SYSFS_REQ_SHOW:
		sysfss_req_show(arg1, (void *)arg2, (void *)arg3);
		break;

	case SCD_MSG_SYSFS_REQ_STORE:
		sysfss_req_store(arg1, (void *)arg2, (void *)arg3, error);
		break;

	case SCD_MSG_SYSFS_REQ_RELEASE:
		sysfss_req_release(arg1, (void *)arg2, (void *)arg3);
		break;

	default:
		kprintf("sysfss_packet_handler:unknown message. msg %d"
				" error %d arg1 %#lx arg2 %#lx arg3 %#lx\n",
				msg, error, arg1, arg2, arg3);
		break;

	}
	return;
} /* sysfss_packet_handler() */

void
sysfs_init(void)
{
	int error;
	struct sysfs_req_setup_param *param = NULL;
	struct ikc_scd_packet packet;

	dkprintf("sysfs_init()\n");

	if ((sizeof(struct sysfs_req_create_param) > PAGE_SIZE)
			|| (sizeof(struct sysfs_req_mkdir_param) > PAGE_SIZE)
			|| (sizeof(struct sysfs_req_symlink_param) > PAGE_SIZE)
			|| (sizeof(struct sysfs_req_lookup_param) > PAGE_SIZE)
			|| (sizeof(struct sysfs_req_unlink_param) > PAGE_SIZE)
			|| (sizeof(struct sysfs_req_setup_param) > PAGE_SIZE)) {
		panic("struct sysfs_*_req_param too large");
	}

	sysfs_data_bufsize = PAGE_SIZE;
	sysfs_data_buf = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!sysfs_data_buf) {
		error = -ENOMEM;
		ekprintf("sysfs_init:allocate_pages(buf) failed. %d\n", error);
		goto out;
	}

	param = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!param) {
		error = -ENOMEM;
		ekprintf("sysfs_init:allocate_pages(param) failed. %d\n",
				error);
		goto out;
	}

	param->busy = 1;
	param->buf_rpa = virt_to_phys(sysfs_data_buf);
	param->bufsize = PAGE_SIZE;

	packet.msg = SCD_MSG_SYSFS_REQ_SETUP;
	packet.sysfs_arg1 = virt_to_phys(param);

	error = ihk_ikc_send(cpu_local_var(ikc2linux), &packet, 0);
	if (error) {
		ekprintf("sysfs_init:ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (param->busy) {
		cpu_pause();
	}
	rmb();

	error = param->error;
	if (error) {
		ekprintf("sysfs_init:SCD_MSG_SYSFS_REQ_SETUP failed. %d\n",
				error);
		goto out;
	}

	error = 0;
out:
	if (param) {
		ihk_mc_free_pages(param, 1);
	}
	if (error) {
		ekprintf("sysfs_init(): %d\n", error);
		panic("sysfs_init");
	}
	dkprintf("sysfs_init():\n");
	return;
} /* sysfs_init() */

/**** End of File ****/
