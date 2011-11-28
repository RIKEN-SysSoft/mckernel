#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <ikc/master.h>

static unsigned long read_tsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a"(low), "=d"(high));
 
	return (low | ((unsigned long)high << 32));
}


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


static int test_packet_handler(struct aal_ikc_channel_desc *c,
                                void *__packet, void *__os)
{
	struct ikc_test_packet *packet = __packet;
	struct ikc_test_packet p;
	int i;
	unsigned long a, pp, *v;
	       
	if (packet->msg == 0x11110011) {
		kprintf("Test msg : %x, %x\n", packet->msg);
		a = (unsigned long)packet->param1 << 12;
		
		pp = aal_mc_map_memory(NULL, a, 4 * 1024 * 1024);
		v = aal_mc_map_virtual(pp, 4 * 1024,
		                       PTATTR_UNCACHABLE);
		
		testmem(v, 4 * 1024 * 1024);

		aal_mc_unmap_virtual(v, 4 * 1024);
		aal_mc_unmap_memory(NULL, pp, 4 * 1024 * 1024);
	} else if (packet->msg == 0x11110012) {
		p.msg = 0x11110013;
		for (i = 0; i < 10; i++) {
			aal_ikc_send(c, &p, 0);
		}
	}
	
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
