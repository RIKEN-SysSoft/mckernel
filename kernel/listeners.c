#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <ikc/master.h>

static int test_packet_handler(struct aal_ikc_channel_desc *c,
                                void *__packet, void *__os)
{
	
	return 0;
}
                                
static int test_handler(struct aal_ikc_channel_info *param)
{
	kprintf("Test connected : %p\n", param->channel);

	param->packet_handler = test_packet_handler;

	return 0;
}

static struct aal_ikc_listen_param test_listen_param = {
	.port = 500,
	.handler = test_handler,
	.pkt_size = sizeof(struct ikc_test_packet),
	.queue_size = 4096,
	.magic = 0x29,
};

void mc_ikc_init(void)
{
	aal_ikc_listen_port(NULL, &test_listen_param);
	kprintf("Listener registered port %d\n", 500);
}
