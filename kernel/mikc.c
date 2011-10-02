#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/debug.h>
#include <aal/ikc.h>

static struct aal_ikc_channel_desc mchannel;
static int master_channel_packet_handler(void *__packet, void *arg);

void ikc_master_init(void)
{
	aal_mc_ikc_init_first(&mchannel, master_channel_packet_handler);
	kprintf("done.\n");
}

static int master_channel_packet_handler(void *__packet, void *arg)
{
	struct aal_ikc_master_packet *packet = __packet;

	/* Do something */
	kprintf("Packet = %p\n", packet);
	kprintf("Master packet! : %x\n", packet->msg);

	switch (packet->msg) {
	case MASTER_PACKET_INIT_ACK:
		aal_ikc_send(&mchannel, packet, 0);
		break;
	}

	return 0;
}

