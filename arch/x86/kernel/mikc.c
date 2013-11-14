/**
 * \file mikc.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Initialize Inter-Kernel Communication (IKC)
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */

#include <ihk/ikc.h>
#include <ihk/lock.h>
#include <ikc/msg.h>
#include <memory.h>
#include <string.h>

extern void arch_set_mikc_queue(void *r, void *w);
ihk_ikc_ph_t arch_master_channel_packet_handler;

int ihk_mc_ikc_init_first_local(struct ihk_ikc_channel_desc *channel,
                                ihk_ikc_ph_t packet_handler)
{
	struct ihk_ikc_queue_head *rq, *wq;

	ihk_ikc_system_init(NULL);

	memset(channel, 0, sizeof(struct ihk_ikc_channel_desc));

	/* Place both sides in this side */
	rq = arch_alloc_page(IHK_MC_AP_CRITICAL);
	wq = arch_alloc_page(IHK_MC_AP_CRITICAL);

	ihk_ikc_init_queue(rq, 0, 0, PAGE_SIZE, MASTER_IKCQ_PKTSIZE);
	ihk_ikc_init_queue(wq, 0, 0, PAGE_SIZE, MASTER_IKCQ_PKTSIZE);

	arch_master_channel_packet_handler = packet_handler;

	ihk_ikc_init_desc(channel, IKC_OS_HOST, 0, rq, wq,
	                  ihk_ikc_master_channel_packet_handler);
	ihk_ikc_enable_channel(channel);

	/* Set boot parameter */
	arch_set_mikc_queue(rq, wq);

	return 0;
}
