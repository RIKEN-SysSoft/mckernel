#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <ikc/msg.h>

static struct aal_ikc_channel_desc mchannel;
static int arch_master_channel_packet_handler(struct aal_ikc_channel_desc *,
                                         void *__packet, void *arg);

void ikc_master_init(void)
{
	aal_mc_ikc_init_first(&mchannel, arch_master_channel_packet_handler);
	kprintf("done.\n");
}

static int arch_master_channel_packet_handler(struct aal_ikc_channel_desc *c,
                                              void *__packet, void *arg)
{
	struct aal_ikc_master_packet *packet = __packet;

	switch (packet->msg) {
	case MASTER_PACKET_INIT_ACK:
		kprintf("Master channel init acked.\n");
		aal_ikc_send(&mchannel, packet, 0);
		break;
	}

	return 0;
}

struct aal_ikc_channel_desc *aal_mc_get_master_channel(void)
{
	return &mchannel;
}
