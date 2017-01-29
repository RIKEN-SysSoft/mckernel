/**
 * \file mikc.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Initialize Inter-Kernel Communication (IKC)
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <ihk/ikc.h>
#include <ihk/lock.h>
#include <ikc/msg.h>
#include <memory.h>
#include <string.h>

extern int num_processors;
extern void arch_set_mikc_queue(void *r, void *w);
ihk_ikc_ph_t arch_master_channel_packet_handler;

int ihk_mc_ikc_init_first_local(struct ihk_ikc_channel_desc *channel,
                                ihk_ikc_ph_t packet_handler)
{
	struct ihk_ikc_queue_head *rq, *wq;
	size_t mikc_queue_pages;

	ihk_ikc_system_init(NULL);

	memset(channel, 0, sizeof(struct ihk_ikc_channel_desc));

	mikc_queue_pages = ((2 * num_processors * MASTER_IKCQ_PKTSIZE)
			+ (PAGE_SIZE - 1)) / PAGE_SIZE;

	/* Place both sides in this side */
	rq = ihk_mc_alloc_pages(mikc_queue_pages, IHK_MC_AP_CRITICAL);
	wq = ihk_mc_alloc_pages(mikc_queue_pages, IHK_MC_AP_CRITICAL);

	ihk_ikc_init_queue(rq, 0, 0,
			mikc_queue_pages * PAGE_SIZE, MASTER_IKCQ_PKTSIZE);
	ihk_ikc_init_queue(wq, 0, 0,
			mikc_queue_pages * PAGE_SIZE, MASTER_IKCQ_PKTSIZE);

	arch_master_channel_packet_handler = packet_handler;

	ihk_ikc_init_desc(channel, IKC_OS_HOST, 0, rq, wq,
	                  ihk_ikc_master_channel_packet_handler, channel);
	ihk_ikc_enable_channel(channel);

	/* Set boot parameter */
	arch_set_mikc_queue(rq, wq);

	return 0;
}
