#include <aal/ikc.h>
#include <aal/lock.h>
#include <ikc/msg.h>
#include <memory.h>
#include <string.h>

extern void arch_set_mikc_queue(void *r, void *w);
aal_ikc_ph_t arch_master_channel_packet_handler;

int aal_mc_ikc_init_first_local(struct aal_ikc_channel_desc *channel,
                                aal_ikc_ph_t packet_handler)
{
	struct aal_ikc_queue_head *rq, *wq;

	aal_ikc_system_init(NULL);

	memset(channel, 0, sizeof(struct aal_ikc_channel_desc));

	/* Place both sides in this side */
	rq = arch_alloc_page(0);
	wq = arch_alloc_page(0);

	aal_ikc_init_queue(rq, 0, 0, PAGE_SIZE, MASTER_IKCQ_PKTSIZE);
	aal_ikc_init_queue(wq, 0, 0, PAGE_SIZE, MASTER_IKCQ_PKTSIZE);

	arch_master_channel_packet_handler = packet_handler;

	aal_ikc_init_desc(channel, IKC_OS_HOST, 0, rq, wq,
	                  aal_ikc_master_channel_packet_handler);
	aal_ikc_enable_channel(channel);

	/* Set boot parameter */
	arch_set_mikc_queue(rq, wq);

	return 0;
}
