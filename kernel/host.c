#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <ikc/master.h>
#include <syscall.h>
#include <cls.h>
#include <process.h>
#include <page.h>

/*
 * Communication with host 
 */
static void process_msg_prepare_process(unsigned long rphys)
{
	unsigned long phys, sz, s, e, up;
	struct program_load_desc *p, *pn;
	int i, npages, n;
	struct process *proc;
	unsigned long addr;

	sz = sizeof(struct program_load_desc)
		+ sizeof(struct program_image_section) * 16;
	npages = (sz + PAGE_SIZE - 1) >> PAGE_SHIFT;

	phys = aal_mc_map_memory(NULL, rphys, sz);
	p = aal_mc_map_virtual(phys, npages, PTATTR_WRITABLE);

	n = p->num_sections;
	kprintf("# of sections: %d\n", n);

	pn = aal_mc_allocate(sizeof(struct program_load_desc) 
	                     + sizeof(struct program_image_section) * n, 0);
	memcpy_long(pn, p, sizeof(struct program_load_desc) 
	            + sizeof(struct program_image_section) * n);

	proc = create_process(p->entry);
	proc->pid = p->pid;

	/* TODO: Clear it at the proper timing */
	cpu_local_var(scp).post_idx = 0;

	for (i = 0; i < n; i++) {
		s = (pn->sections[i].vaddr) & PAGE_MASK;
		e = (pn->sections[i].vaddr + pn->sections[i].len
		     + PAGE_SIZE - 1) & PAGE_MASK;
		up = virt_to_phys(aal_mc_alloc_pages((e - s) >> PAGE_SHIFT, 0));

		add_process_memory_range(proc, s, e, up, 0);
		p->sections[i].remote_pa = up;

		/* TODO: Maybe we need flag */
		if (i == 0) {
			proc->vm->region.text_start = s;
			proc->vm->region.text_end = e;
		} else if (i == 1) {
			proc->vm->region.data_start = s;
			proc->vm->region.data_end = e;
		} else {
			proc->vm->region.data_start =
				(s < proc->vm->region.data_start ? 
				 s : proc->vm->region.data_start);
			proc->vm->region.data_end = 
				(e > proc->vm->region.data_end ? 
				 e : proc->vm->region.data_end);
		}
	}
	proc->vm->region.brk_start = proc->vm->region.brk_end =
		proc->vm->region.data_end;
	proc->vm->region.map_start = proc->vm->region.map_end = 
		(USER_END / 3) & LARGE_PAGE_MASK;

	/* Map system call stuffs */
	addr = proc->vm->region.map_start - PAGE_SIZE * SCD_RESERVED_COUNT;
	e = addr + PAGE_SIZE * DOORBELL_PAGE_COUNT;
	add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).doorbell_pa,
	                         VR_REMOTE | VR_RESERVED);
	addr = e;
	e = addr + PAGE_SIZE * REQUEST_PAGE_COUNT;
	add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).request_pa,
	                         VR_REMOTE | VR_RESERVED);
	addr = e;
	e = addr + PAGE_SIZE * RESPONSE_PAGE_COUNT;
	add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).response_pa,
	                         VR_RESERVED);

	p->rprocess = (unsigned long)proc;
	init_process_stack(proc);

	kprintf("new process : %p [%d] / table : %p\n", proc, proc->pid,
	        proc->vm->page_table);

	aal_mc_free(pn);

	aal_mc_unmap_virtual(p, npages);
	aal_mc_unmap_memory(NULL, phys, sz);
}

static void process_msg_init(struct ikc_scd_init_param *pcp)
{
	struct syscall_params *lparam;

	lparam = &cpu_local_var(scp);
	lparam->response_va = allocate_pages(RESPONSE_PAGE_COUNT, 0);
	lparam->response_pa = virt_to_phys(lparam->response_va);

	pcp->request_page = 0;
	pcp->doorbell_page = 0;
	pcp->response_page = lparam->response_pa;
}

static void process_msg_init_acked(unsigned long pphys)
{
	struct ikc_scd_init_param *param = (void *)pphys;
	struct syscall_params *lparam;

	lparam = &cpu_local_var(scp);
	lparam->request_rpa = param->request_page;
	lparam->request_pa = aal_mc_map_memory(NULL, param->request_page,
	                                       REQUEST_PAGE_COUNT * PAGE_SIZE);
	lparam->request_va = aal_mc_map_virtual(lparam->request_pa,
	                                        REQUEST_PAGE_COUNT,
	                                        PTATTR_WRITABLE);

	lparam->doorbell_rpa = param->doorbell_page;
	lparam->doorbell_pa = aal_mc_map_memory(NULL, param->doorbell_page,
	                                        DOORBELL_PAGE_COUNT * 
	                                        PAGE_SIZE);
	lparam->doorbell_va = aal_mc_map_virtual(lparam->doorbell_pa,
	                                         DOORBELL_PAGE_COUNT,
	                                         PTATTR_WRITABLE);

	lparam->post_rpa = param->post_page;
	lparam->post_pa = aal_mc_map_memory(NULL, param->post_page,
	                                    PAGE_SIZE);
	lparam->post_va = aal_mc_map_virtual(lparam->post_pa, 1,
	                                     PTATTR_WRITABLE);

	lparam->post_fin = 1;

	kprintf("Syscall parameters: (%d)\n", aal_mc_get_processor_id());
	kprintf(" Response: %lx, %p\n",
	        lparam->response_pa, lparam->response_va);
	kprintf(" Request : %lx, %lx, %p\n",
	        lparam->request_pa, lparam->request_rpa, lparam->request_va);
	kprintf(" Doorbell: %lx, %lx, %p\n",
	        lparam->doorbell_pa, lparam->doorbell_rpa, lparam->doorbell_va);
	kprintf(" Post: %lx, %lx, %p\n",
	        lparam->post_pa, lparam->post_rpa, lparam->post_va);
}

static void syscall_channel_send(struct aal_ikc_channel_desc *c,
                                 struct ikc_scd_packet *packet)
{
	aal_ikc_send(c, packet, 0);
}

static int syscall_packet_handler(struct aal_ikc_channel_desc *c,
                                  void *__packet, void *aal_os)
{
	struct ikc_scd_packet *packet = __packet;
	struct ikc_scd_packet pckt;

	switch (packet->msg) {
	case SCD_MSG_INIT_CHANNEL_ACKED:
		kprintf("init channel acked!\n");
		process_msg_init_acked(packet->arg);
		return 0;

	case SCD_MSG_PREPARE_PROCESS:
		process_msg_prepare_process(packet->arg);

		pckt.msg = SCD_MSG_PREPARE_PROCESS_ACKED;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		syscall_channel_send(c, &pckt);

		return 0;

	case SCD_MSG_SCHEDULE_PROCESS:
		kprintf("next one : %lx\n", packet->arg);

		cpu_local_var(next) = (struct process *)packet->arg;
		return 0;
	}
	return 0;
}

void init_host_syscall_channel(void)
{
	struct aal_ikc_connect_param param;
	struct ikc_scd_packet pckt;

	param.port = 501;
	param.pkt_size = sizeof(struct ikc_scd_packet);
	param.queue_size = PAGE_SIZE;
	param.magic = 0x1129;
	param.handler = syscall_packet_handler;

	kprintf("(syscall) Trying to connect host ...");
	while (aal_ikc_connect(NULL, &param) != 0) {
		kprintf(".");
		aal_mc_delay_us(1000 * 1000);
	}
	kprintf("connected.\n");

	get_this_cpu_local_var()->syscall_channel = param.channel;

	process_msg_init(&cpu_local_var(iip));
	pckt.msg = SCD_MSG_INIT_CHANNEL;
	pckt.ref = aal_mc_get_processor_id();
	pckt.arg = virt_to_phys(&cpu_local_var(iip));
	syscall_channel_send(param.channel, &pckt);
}
