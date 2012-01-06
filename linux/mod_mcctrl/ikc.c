#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "mcctrl.h"
#include <aal/ikc.h>
#include <ikc/master.h>

int num_channels;

struct mcctrl_channel *channels;

void mcexec_prepare_ack(unsigned long arg);
static void mcctrl_ikc_init(aal_os_t os, int cpu, unsigned long rphys);
int mcexec_syscall(struct mcctrl_channel *c, unsigned long arg);

static int syscall_packet_handler(struct aal_ikc_channel_desc *c,
                                  void *__packet, void *__os)
{
	struct ikc_scd_packet *pisp = __packet;

	switch (pisp->msg) {
	case SCD_MSG_INIT_CHANNEL:
		mcctrl_ikc_init(__os, pisp->ref, pisp->arg);
		break;

	case SCD_MSG_PREPARE_PROCESS_ACKED:
		mcexec_prepare_ack(pisp->arg);
		break;

	case SCD_MSG_SYSCALL_ONESIDE:
		mcexec_syscall(channels + pisp->ref, pisp->arg);
		break;
	}

	return 0;
}

int mcctrl_ikc_send(int cpu, struct ikc_scd_packet *pisp)
{
	if (cpu < 0 || cpu >= num_channels || !channels[cpu].c) {
		return -EINVAL;
	}
	return aal_ikc_send(channels[cpu].c, pisp, 0);
}

int mcctrl_ikc_send_msg(int cpu, int msg, int ref, unsigned long arg)
{
	struct ikc_scd_packet packet;

	if (cpu < 0 || cpu >= num_channels || !channels[cpu].c) {
		return -EINVAL;
	}

	packet.msg = msg;
	packet.ref = ref;
	packet.arg = arg;

	return aal_ikc_send(channels[cpu].c, &packet, 0);
}

int mcctrl_ikc_set_recv_cpu(int cpu)
{
	aal_ikc_channel_set_cpu(channels[cpu].c,
	                        aal_ikc_get_processor_id());
	kprintf("Setting the target to %d\n",
	        aal_ikc_get_processor_id());
	return 0;
}

int mcctrl_ikc_is_valid_thread(int cpu)
{
	if (cpu < 0 || cpu >= num_channels || !channels[cpu].c) {
		return 0;
	} else {
		return 1;
	}
}

unsigned long *mcctrl_doorbell_va;
unsigned long mcctrl_doorbell_pa;

static void mcctrl_ikc_init(aal_os_t os, int cpu, unsigned long rphys)
{
	struct ikc_scd_packet packet;
	struct mcctrl_channel *pmc = channels + cpu;
	unsigned long phys;
	struct ikc_scd_init_param *rpm;

	if (!pmc) {
		return;
	}

	printk("IKC init: %d\n", cpu);

	phys = aal_device_map_memory(aal_os_to_dev(os), rphys,
	                             sizeof(struct ikc_scd_init_param));
	rpm = ioremap_wc(phys, sizeof(struct ikc_scd_init_param));

	pmc->param.request_va = (void *)__get_free_pages(GFP_KERNEL, 4);
	pmc->param.request_pa = virt_to_phys(pmc->param.request_va);
	pmc->param.doorbell_va = mcctrl_doorbell_va;
	pmc->param.doorbell_pa = mcctrl_doorbell_pa;
	pmc->param.post_va = (void *)__get_free_page(GFP_KERNEL);
	pmc->param.post_pa = virt_to_phys(pmc->param.post_va);
	memset(pmc->param.doorbell_va, 0, PAGE_SIZE);
	memset(pmc->param.request_va, 0, PAGE_SIZE);
	memset(pmc->param.post_va, 0, PAGE_SIZE);
	
	pmc->param.response_rpa = rpm->response_page;
	pmc->param.response_pa 
		= aal_device_map_memory(aal_os_to_dev(os),
		                        pmc->param.response_rpa,
		                        PAGE_SIZE);
	pmc->param.response_va = ioremap_cache(pmc->param.response_pa,
	                                       PAGE_SIZE);

	pmc->dma_buf = (void *)__get_free_pages(GFP_KERNEL,
	                                        DMA_PIN_SHIFT - PAGE_SHIFT);

	rpm->request_page = pmc->param.request_pa;
	rpm->doorbell_page = pmc->param.doorbell_pa;
	rpm->post_page = pmc->param.post_pa;

	packet.msg = SCD_MSG_INIT_CHANNEL_ACKED;
	packet.ref = cpu;
	packet.arg = rphys;

	printk("Request: %lx, Response: %lx, Doorbell: %lx\n",
	       pmc->param.request_pa, pmc->param.response_rpa,
	       pmc->param.doorbell_pa);
	printk("Request: %p, Response: %p, Doorbell: %p\n",
	       pmc->param.request_va, pmc->param.response_va,
	       pmc->param.doorbell_va);

	aal_ikc_send(pmc->c, &packet, 0);

	iounmap(rpm);

	aal_device_unmap_memory(aal_os_to_dev(os), phys,
	                        sizeof(struct ikc_scd_init_param));
}

static int connect_handler(struct aal_ikc_channel_info *param)
{
	struct aal_ikc_channel_desc *c;
	int cpu;

	c = param->channel;
	cpu = c->send.queue->read_cpu;

	if (cpu < 0 || cpu >= num_channels) {
		kprintf("Invalid connect source processor: %d\n", cpu);
		return 1;
	}
	param->packet_handler = syscall_packet_handler;
	init_waitqueue_head(&channels[cpu].wq_syscall);

	channels[cpu].c = c;
	kprintf("syscall: MC CPU %d connected.\n", cpu);

	return 0;
}

static struct aal_ikc_listen_param listen_param = {
	.port = 501,
	.handler = connect_handler,
	.pkt_size = sizeof(struct ikc_scd_packet),
	.queue_size = PAGE_SIZE,
	.magic = 0x1129,
};

int prepare_ikc_channels(aal_os_t os)
{
	struct aal_cpu_info *info;

	mcctrl_doorbell_va = (void *)__get_free_page(GFP_KERNEL);
	mcctrl_doorbell_pa = virt_to_phys(mcctrl_doorbell_va);

	info = aal_os_get_cpu_info(os);
	if (!info) {
		printk("Error: cannot retrieve CPU info.\n");
		return -EINVAL;
	}
	if (info->n_cpus < 1) {
		printk("Error: # of cpu is invalid.\n");
		return -EINVAL;
	}

	num_channels = info->n_cpus;
	channels = kzalloc(sizeof(struct mcctrl_channel) * num_channels,
	                   GFP_KERNEL);
	if (!channels) {
		printk("Error: cannot allocate channels.\n");
		return -ENOMEM;
	}
	
	aal_ikc_listen_port(os, &listen_param);
	return 0;
}
