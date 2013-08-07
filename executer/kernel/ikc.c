#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "mcctrl.h"
#ifdef ATTACHED_MIC
#include <sysdeps/mic/mic/micconst.h>
#endif

#define REQUEST_SHIFT    16

//int num_channels;

//struct mcctrl_channel *channels;

void mcexec_prepare_ack(ihk_os_t os, unsigned long arg, int err);
static void mcctrl_ikc_init(ihk_os_t os, int cpu, unsigned long rphys);
int mcexec_syscall(struct mcctrl_channel *c, unsigned long arg);

static int syscall_packet_handler(struct ihk_ikc_channel_desc *c,
                                  void *__packet, void *__os)
{
	struct ikc_scd_packet *pisp = __packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(__os);

	switch (pisp->msg) {
	case SCD_MSG_INIT_CHANNEL:
		mcctrl_ikc_init(__os, pisp->ref, pisp->arg);
		break;

	case SCD_MSG_PREPARE_PROCESS_ACKED:
		mcexec_prepare_ack(__os, pisp->arg, 0);
		break;

	case SCD_MSG_PREPARE_PROCESS_NACKED:
		mcexec_prepare_ack(__os, pisp->arg, pisp->err);
		break;

	case SCD_MSG_SYSCALL_ONESIDE:
		mcexec_syscall(usrdata->channels + pisp->ref, pisp->arg);
		break;
	}

	return 0;
}

int mcctrl_ikc_send(ihk_os_t os, int cpu, struct ikc_scd_packet *pisp)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	if (cpu < 0 || cpu >= usrdata->num_channels || !usrdata->channels[cpu].c) {
		return -EINVAL;
	}
	return ihk_ikc_send(usrdata->channels[cpu].c, pisp, 0);
}

int mcctrl_ikc_send_msg(ihk_os_t os, int cpu, int msg, int ref, unsigned long arg)
{
	struct ikc_scd_packet packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	if (cpu < 0 || cpu >= usrdata->num_channels || !usrdata->channels[cpu].c) {
		return -EINVAL;
	}

	packet.msg = msg;
	packet.ref = ref;
	packet.arg = arg;

	return ihk_ikc_send(usrdata->channels[cpu].c, &packet, 0);
}

int mcctrl_ikc_set_recv_cpu(ihk_os_t os, int cpu)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	ihk_ikc_channel_set_cpu(usrdata->channels[cpu].c,
	                        ihk_ikc_get_processor_id());
	kprintf("Setting the target to %d\n",
	        ihk_ikc_get_processor_id());
	return 0;
}

int mcctrl_ikc_is_valid_thread(ihk_os_t os, int cpu)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	if (cpu < 0 || cpu >= usrdata->num_channels || !usrdata->channels[cpu].c) {
		return 0;
	} else {
		return 1;
	}
}

//unsigned long *mcctrl_doorbell_va;
//unsigned long mcctrl_doorbell_pa;

static void mcctrl_ikc_init(ihk_os_t os, int cpu, unsigned long rphys)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet packet;
	struct mcctrl_channel *pmc = usrdata->channels + cpu;
	unsigned long phys;
	struct ikc_scd_init_param *rpm;

	if (!pmc) {
		return;
	}

	printk("IKC init: %d\n", cpu);

	phys = ihk_device_map_memory(ihk_os_to_dev(os), rphys,
	                             sizeof(struct ikc_scd_init_param));
#ifdef CONFIG_MIC
	rpm = ioremap_wc(phys, sizeof(struct ikc_scd_init_param));
#else
	rpm = ihk_device_map_virtual(ihk_os_to_dev(os), phys, 
	                             sizeof(struct ikc_scd_init_param),
								 NULL, 0);
#endif

	pmc->param.request_va =
		(void *)__get_free_pages(GFP_KERNEL,
		                         REQUEST_SHIFT - PAGE_SHIFT);
	pmc->param.request_pa = virt_to_phys(pmc->param.request_va);
	pmc->param.doorbell_va = usrdata->mcctrl_doorbell_va;
	pmc->param.doorbell_pa = usrdata->mcctrl_doorbell_pa;
	pmc->param.post_va = (void *)__get_free_page(GFP_KERNEL);
	pmc->param.post_pa = virt_to_phys(pmc->param.post_va);
	memset(pmc->param.doorbell_va, 0, PAGE_SIZE);
	memset(pmc->param.request_va, 0, PAGE_SIZE);
	memset(pmc->param.post_va, 0, PAGE_SIZE);
	
	pmc->param.response_rpa = rpm->response_page;
	pmc->param.response_pa 
		= ihk_device_map_memory(ihk_os_to_dev(os),
		                        pmc->param.response_rpa,
		                        PAGE_SIZE);
#ifdef CONFIG_MIC							
	pmc->param.response_va = ioremap_cache(pmc->param.response_pa,
	                                       PAGE_SIZE);
#else
	pmc->param.response_va = ihk_device_map_virtual(ihk_os_to_dev(os), 
	                                                pmc->param.response_pa,
													PAGE_SIZE, NULL, 0);
#endif

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

	ihk_ikc_send(pmc->c, &packet, 0);

#ifdef CONFIG_MIC							
	iounmap(rpm);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), rpm, 
	                         sizeof(struct ikc_scd_init_param));
#endif

	ihk_device_unmap_memory(ihk_os_to_dev(os), phys,
	                        sizeof(struct ikc_scd_init_param));
}

static int connect_handler(struct ihk_ikc_channel_info *param)
{
	struct ihk_ikc_channel_desc *c;
	int cpu;
	ihk_os_t os = param->channel->remote_os;
	struct mcctrl_usrdata   *usrdata = ihk_host_os_get_usrdata(os);

	c = param->channel;
	cpu = c->send.queue->read_cpu;

	if (cpu < 0 || cpu >= usrdata->num_channels) {
		kprintf("Invalid connect source processor: %d\n", cpu);
		return 1;
	}
	param->packet_handler = syscall_packet_handler;
	init_waitqueue_head(&usrdata->channels[cpu].wq_syscall);

	usrdata->channels[cpu].c = c;
	kprintf("syscall: MC CPU %d connected.\n", cpu);

	return 0;
}

static struct ihk_ikc_listen_param listen_param = {
	.port = 501,
	.handler = connect_handler,
	.pkt_size = sizeof(struct ikc_scd_packet),
	.queue_size = PAGE_SIZE,
	.magic = 0x1129,
};

int prepare_ikc_channels(ihk_os_t os)
{
	struct ihk_cpu_info *info;
	struct mcctrl_usrdata   *usrdata;
	int error;

	usrdata = kzalloc(sizeof(struct mcctrl_usrdata), GFP_KERNEL);
	usrdata->mcctrl_doorbell_va = (void *)__get_free_page(GFP_KERNEL);
	usrdata->mcctrl_doorbell_pa = virt_to_phys(usrdata->mcctrl_doorbell_va);

	info = ihk_os_get_cpu_info(os);
	if (!info) {
		printk("Error: cannot retrieve CPU info.\n");
		return -EINVAL;
	}
	if (info->n_cpus < 1) {
		printk("Error: # of cpu is invalid.\n");
		return -EINVAL;
	}

	usrdata->num_channels = info->n_cpus;
	usrdata->channels = kzalloc(sizeof(struct mcctrl_channel) * usrdata->num_channels,
	                   GFP_KERNEL);
	if (!usrdata->channels) {
		printk("Error: cannot allocate channels.\n");
		return -ENOMEM;
	}

	usrdata->os = os;
	init_waitqueue_head(&usrdata->wq_prepare);
	ihk_host_os_set_usrdata(os, usrdata);
	memcpy(&usrdata->listen_param, &listen_param, sizeof listen_param);
	ihk_ikc_listen_port(os, &usrdata->listen_param);

	error = init_peer_channel_registry(usrdata);
	if (error) {
		return error;
	}

	return 0;
}

void __destroy_ikc_channel(ihk_os_t os, struct mcctrl_channel *pmc)
{
	free_pages((unsigned long)pmc->param.request_va,
	           REQUEST_SHIFT - PAGE_SHIFT);
	free_page((unsigned long)pmc->param.post_va);

#ifdef CONFIG_MIC
	iounmap(pmc->param.response_va);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), pmc->param.response_va, 
	                         PAGE_SIZE);
#endif
	ihk_device_unmap_memory(ihk_os_to_dev(os),
	                        pmc->param.response_pa, PAGE_SIZE);
	free_pages((unsigned long)pmc->dma_buf,
	           DMA_PIN_SHIFT - PAGE_SHIFT);
}

void destroy_ikc_channels(ihk_os_t os)
{
	int i;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	ihk_host_os_set_usrdata(os, NULL);

	for (i = 0; i < usrdata->num_channels; i++) {
		if (usrdata->channels[i].c) {
//			ihk_ikc_disconnect(usrdata->channels[i].c);
			ihk_ikc_free_channel(usrdata->channels[i].c);
			__destroy_ikc_channel(os, usrdata->channels + i);
			printk("Channel #%d freed.\n", i);
		}
	}
	free_page((unsigned long)usrdata->mcctrl_doorbell_va);

	kfree(usrdata->channels);
	kfree(usrdata);
}
