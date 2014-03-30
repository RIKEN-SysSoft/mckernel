/**
 * \file copy.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Memory copy using DMA controller
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifdef USE_DMA
#include <ihk/dma.h>
#include <amemcpy.h>

int memcpy_async(unsigned long dest, unsigned long src,
                 unsigned long len, int wait, unsigned long *notify)
{
	struct ihk_dma_request req;
	unsigned long fin = 0;

	if (notify)
		*notify = 0;
	memset(&req, 0, sizeof(req));
	/* Physical */
	req.src_os = (ihk_os_t)IHK_THIS_OS;
	req.src_phys = src;
	req.dest_os = (ihk_os_t)IHK_THIS_OS;
	req.dest_phys = dest;
	req.size = len;

	if (notify) {
		req.notify_os = (ihk_os_t)IHK_THIS_OS;
		req.notify = (void *)virt_to_phys(notify);
		req.priv = (void *)1;
	} else if (wait) {
		req.notify_os = (ihk_os_t)IHK_THIS_OS;
		req.notify = (void *)virt_to_phys(&fin);
		req.priv = (void *)1;
	}

	ihk_mc_dma_request(0, &req);
	if (wait) {
		while (!fin) {
			barrier();
		}
	}

	return 0;
}
#endif
