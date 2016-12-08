/**
 * \file mikc.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Initialization of IKC master channel
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/msg.h>
#include <kmalloc.h>

static struct ihk_ikc_channel_desc *mchannel;
static int arch_master_channel_packet_handler(struct ihk_ikc_channel_desc *,
                                         void *__packet, void *arg);

void ihk_ikc_master_init(void)
{
	mchannel = kmalloc(sizeof(struct ihk_ikc_channel_desc) +
	                   sizeof(struct ihk_ikc_master_packet),
	                   IHK_MC_AP_CRITICAL);

	ihk_mc_ikc_init_first(mchannel, arch_master_channel_packet_handler);
}

extern int host_ikc_inited;

static int arch_master_channel_packet_handler(struct ihk_ikc_channel_desc *c,
                                              void *__packet, void *arg)
{
	struct ihk_ikc_master_packet *packet = __packet;

	switch (packet->msg) {
	case IHK_IKC_MASTER_MSG_INIT_ACK:
		kprintf("Master channel init acked.\n");
		host_ikc_inited = 1;
		break;
	}

	return 0;
}

struct ihk_ikc_channel_desc *ihk_mc_get_master_channel(void)
{
	return mchannel;
}
