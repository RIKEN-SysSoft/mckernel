/**
 * \file listeners.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Usage example of ihk_ikc_listen_port()
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/master.h>
#include <arch/cpu.h>

//#define DEBUG_LISTENERS

#ifdef DEBUG_LISTENERS
#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#else
#define dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#endif

void testmem(void *v, unsigned long size)
{
	unsigned long i, st, ed, s = 0;
	unsigned long *p = v;

	for (i = 0; i < size; i += 8) {
		s += *(unsigned long *)((char *)p + i);
	}

	st = read_tsc();
	for (i = 0; i < size; i += 64) {
		s += *(unsigned long *)((char *)p + i);
	}
	ed = read_tsc();

	kprintf("%ld, %ld\n", ed - st, s);
}


static int test_packet_handler(struct ihk_ikc_channel_desc *c,
                                void *__packet, void *__os)
{
	struct ikc_test_packet *packet = __packet;
	struct ikc_test_packet p;
	int i;
	unsigned long a, pp, *v;
	       
	if (packet->msg == 0x11110011) {
		kprintf("Test msg : %x, %x\n", packet->msg);
		a = (unsigned long)packet->param1 << 12;
		
		pp = ihk_mc_map_memory(NULL, a, 4 * 1024 * 1024);
		if((v = ihk_mc_map_virtual(pp, 4 * 1024,
		                       PTATTR_UNCACHABLE)) == NULL){
			ihk_mc_unmap_memory(NULL, pp, 4 * 1024 * 1024);
			kprintf("Test msg : Not enough space\n");
			return 0;
		}
		
		testmem(v, 4 * 1024 * 1024);

		ihk_mc_unmap_virtual(v, 4 * 1024, 1);
		ihk_mc_unmap_memory(NULL, pp, 4 * 1024 * 1024);
	} else if (packet->msg == 0x11110012) {
		p.msg = 0x11110013;
		for (i = 0; i < 10; i++) {
			ihk_ikc_send(c, &p, 0);
		}
	} else if (packet->msg == 0x1111001a) {
		kprintf("Packet, I am %d.\n", ihk_mc_get_processor_id());
	}
	
	return 0;
}
                                
static int test_handler(struct ihk_ikc_channel_info *param)
{
	kprintf("Test connected : %p\n", param->channel);

	param->packet_handler = test_packet_handler;

	return 0;
}

static struct ihk_ikc_listen_param test_listen_param = {
	.port = 500,
	.handler = test_handler,
	.pkt_size = sizeof(struct ikc_test_packet),
	.queue_size = 4096,
	.magic = 0x29,
};

void mc_ikc_test_init(void)
{
	ihk_ikc_listen_port(NULL, &test_listen_param);
	dkprintf("Listener registered port %d\n", 500);
}
