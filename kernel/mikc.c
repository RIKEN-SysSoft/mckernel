#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/msg.h>
#include <kmalloc.h>

static struct aal_ikc_channel_desc *mchannel;
static int arch_master_channel_packet_handler(struct aal_ikc_channel_desc *,
                                         void *__packet, void *arg);

void ikc_master_init(void)
{
	mchannel = kmalloc(sizeof(struct aal_ikc_channel_desc) +
	                   sizeof(struct aal_ikc_master_packet), 0);

	aal_mc_ikc_init_first(mchannel, arch_master_channel_packet_handler);
}

extern int host_ikc_inited;

static int arch_master_channel_packet_handler(struct aal_ikc_channel_desc *c,
                                              void *__packet, void *arg)
{
	struct aal_ikc_master_packet *packet = __packet;

	switch (packet->msg) {
	case AAL_IKC_MASTER_MSG_INIT_ACK:
		kprintf("Master channel init acked.\n");
		host_ikc_inited = 1;
		break;
	}

	return 0;
}

struct aal_ikc_channel_desc *aal_mc_get_master_channel(void)
{
	return mchannel;
}
