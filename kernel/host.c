#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/master.h>
#include <syscall.h>
#include <cls.h>
#include <process.h>
#include <page.h>

#define DEBUG_PRINT_HOST

#ifdef DEBUG_PRINT_HOST
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

void check_mapping_for_proc(struct process *proc, unsigned long addr)
{
	unsigned long __phys;

	if (ihk_mc_pt_virt_to_phys(proc->vm->page_table, (void*)addr, &__phys)) {
		kprintf("check_map: no mapping for 0x%lX\n", addr);
	}
	else {
		kprintf("check_map: 0x%lX -> 0x%lX\n", addr, __phys);
	}
}

/*
 * Communication with host 
 */
static int process_msg_prepare_process(unsigned long rphys)
{
	unsigned long phys, sz, s, e, up;
	struct program_load_desc *p, *pn;
	int i, npages, n;
	struct process *proc;
	unsigned long addr;
	char *args_envs, *args_envs_r;
	unsigned long args_envs_p, args_envs_rp;
	char **argv;
	int argc, envc, args_envs_npages;
	char **env;
	int range_npages;
	void *up_v;

	sz = sizeof(struct program_load_desc)
		+ sizeof(struct program_image_section) * 16;
	npages = ((rphys + sz - 1) >> PAGE_SHIFT) - (rphys >> PAGE_SHIFT) + 1;

	phys = ihk_mc_map_memory(NULL, rphys, sz);
	if((p = ihk_mc_map_virtual(phys, npages, PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}

	n = p->num_sections;
	dkprintf("# of sections: %d\n", n);

	if((pn = ihk_mc_allocate(sizeof(struct program_load_desc) 
	       + sizeof(struct program_image_section) * n, IHK_MC_AP_NOWAIT)) == NULL){
		ihk_mc_unmap_virtual(p, npages, 0);
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}
	memcpy_long(pn, p, sizeof(struct program_load_desc) 
	            + sizeof(struct program_image_section) * n);

	if((proc = create_process(p->entry)) == NULL){
		ihk_mc_free(pn);
		ihk_mc_unmap_virtual(p, npages, 1);
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}
	proc->pid = pn->pid;
	proc->vm->region.user_start = pn->user_start;
	proc->vm->region.user_end = pn->user_end;

	/* TODO: Clear it at the proper timing */
	cpu_local_var(scp).post_idx = 0;

	for (i = 0; i < n; i++) {
		s = (pn->sections[i].vaddr) & PAGE_MASK;
		e = (pn->sections[i].vaddr + pn->sections[i].len
		     + PAGE_SIZE - 1) & PAGE_MASK;
		range_npages = (e - s) >> PAGE_SHIFT;

#if 0
		if (range_npages <= 256) {
#endif
			if((up_v = ihk_mc_alloc_pages(range_npages, IHK_MC_AP_NOWAIT)) == NULL){
				goto err;
			}
			up = virt_to_phys(up_v);
			if(add_process_memory_range(proc, s, e, up, VR_NONE) != 0){
				ihk_mc_free_pages(up_v, range_npages);
				goto err;
			}
			
			{
				void *_virt = (void *)s;
				unsigned long _phys;
				if (ihk_mc_pt_virt_to_phys(proc->vm->page_table, 
				                       _virt, &_phys)) {
					kprintf("ERROR: no mapping for 0x%lX\n", _virt);
				}
				for (_virt = (void *)s + PAGE_SIZE; 
				     (unsigned long)_virt < e; _virt += PAGE_SIZE) {
					unsigned long __phys;
					if (ihk_mc_pt_virt_to_phys(proc->vm->page_table, 
				                           _virt, &__phys)) {
						kprintf("ERROR: no mapping for 0x%lX\n", _virt);
						panic("mapping");
					}
					if (__phys != _phys + PAGE_SIZE) {
						kprintf("0x%lX + PAGE_SIZE is not physically contigous, from 0x%lX to 0x%lX\n", _virt - PAGE_SIZE, _phys, __phys);
						panic("mondai");
					}
					
					_phys = __phys;
				}
				kprintf("0x%lX -> 0x%lX is physically contigous\n", s, e);
			}
#if 0			
		}
		else {
			up = 0;
			if (add_process_large_range(proc, s, e, VR_NONE, &up)) {
				kprintf("ERROR: not enough memory\n");
				while (1) cpu_halt();
			}
			
			
			{
				void *_virt = (void *)s;
				unsigned long _phys;
				ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
				                       _virt, &_phys);
				for (_virt = (void *)s + PAGE_SIZE; 
				     (unsigned long)_virt < e; _virt += PAGE_SIZE) {
					unsigned long __phys;
					ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
				                       _virt, &__phys);
					if (__phys != _phys + PAGE_SIZE) {
						kprintf("0x%lX + PAGE_SIZE is not physically contigous, from 0x%lX to 0x%lX\n", _virt - PAGE_SIZE, _phys, __phys);
						panic("mondai");
					}
					
					_phys = __phys;
				}
				kprintf("0x%lX -> 0x%lX is physically contigous\n", s, e);
			}
		}
#endif

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
	
#if 1
    /*
      Fix for the problem where brk grows to hit .bss section
      when using dynamically linked executables.
      Test code resides in /home/takagi/project/mpich/src/brk_icc_mic.
      This is because when using
      ld.so (i.e. using shared objects), mckernel/kernel/host.c sets "brk" to
      the end of .bss of ld.so (e.g. 0x21f000), and then ld.so places a
      main-program after this (e.g. 0x400000), so "brk" will hit .bss
      eventually.
    */
	proc->vm->region.brk_start = proc->vm->region.brk_end =
		(USER_END / 4) & LARGE_PAGE_MASK;
#else
	proc->vm->region.brk_start = proc->vm->region.brk_end =
		proc->vm->region.data_end;
#endif
	proc->vm->region.map_start = proc->vm->region.map_end = 
		(USER_END / 3) & LARGE_PAGE_MASK;

	/* Map system call stuffs */
	addr = proc->vm->region.map_start - PAGE_SIZE * SCD_RESERVED_COUNT;
	e = addr + PAGE_SIZE * DOORBELL_PAGE_COUNT;
	if(add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).doorbell_pa,
	                         VR_REMOTE | VR_RESERVED) != 0){
		goto err;
	}
	addr = e;
	e = addr + PAGE_SIZE * REQUEST_PAGE_COUNT;
	if(add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).request_pa,
	                         VR_REMOTE | VR_RESERVED) != 0){
		goto err;
	}
	addr = e;
	e = addr + PAGE_SIZE * RESPONSE_PAGE_COUNT;
	if(add_process_memory_range(proc, addr, e,
	                         cpu_local_var(scp).response_pa,
	                         VR_RESERVED) != 0){
		goto err;
	}

	/* Map, copy and update args and envs */
	addr = e;
	e = addr + PAGE_SIZE * ARGENV_PAGE_COUNT;
	
	if((args_envs = ihk_mc_alloc_pages(ARGENV_PAGE_COUNT, IHK_MC_AP_NOWAIT)) == NULL){
		goto err;
	}
	args_envs_p = virt_to_phys(args_envs);
	
	if(add_process_memory_range(proc, addr, e, args_envs_p, VR_NONE) != 0){
		ihk_mc_free_pages(args_envs, ARGENV_PAGE_COUNT);
		goto err;
	}
	
	dkprintf("args_envs mapping\n");

	dkprintf("args: 0x%lX, args_len: %d\n", p->args, p->args_len);

	// Map in remote physical addr of args and copy it
	args_envs_npages = (p->args_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	dkprintf("args_envs_npages: %d\n", args_envs_npages);
	args_envs_rp = ihk_mc_map_memory(NULL, (unsigned long)p->args, p->args_len);
	dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
	if((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, args_envs_npages, 
	    PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		goto err;
	}
	dkprintf("args_envs_r: 0x%lX\n", args_envs_r);

	dkprintf("args copy, nr: %d\n", *((int*)args_envs_r));
	
	memcpy_long(args_envs, args_envs_r, p->args_len + 8);

	ihk_mc_unmap_virtual(args_envs_r, args_envs_npages, 0);
	ihk_mc_unmap_memory(NULL, args_envs_rp, p->args_len);
				
	dkprintf("envs: 0x%lX, envs_len: %d\n", p->envs, p->envs_len);

	// Map in remote physical addr of envs and copy it after args
	args_envs_npages = (p->envs_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	dkprintf("args_envs_npages: %d\n", args_envs_npages);
	args_envs_rp = ihk_mc_map_memory(NULL, (unsigned long)p->envs, p->envs_len);
	dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
	if((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, args_envs_npages, 
	    PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		goto err;
	}
	dkprintf("args_envs_r: 0x%lX\n", args_envs_r);
	
	dkprintf("envs copy, nr: %d\n", *((int*)args_envs_r));
	
	memcpy_long(args_envs + p->args_len, args_envs_r, p->envs_len + 8);

	ihk_mc_unmap_virtual(args_envs_r, args_envs_npages, 0);
	ihk_mc_unmap_memory(NULL, args_envs_rp, p->envs_len);

	// Update variables
	argc = *((int*)(args_envs));
	dkprintf("argc: %d\n", argc);

	argv = (char **)(args_envs + (sizeof(int)));
	while (*argv) {
		char **_argv = argv;
		dkprintf("%s\n", args_envs + (unsigned long)*argv);
		*argv = (char *)addr + (unsigned long)*argv; // Process' address space!
		argv = ++_argv;
	}
	argv = (char **)(args_envs + (sizeof(int)));
	
	envc = *((int*)(args_envs + p->args_len));
	dkprintf("envc: %d\n", envc);

	env = (char **)(args_envs + p->args_len + sizeof(int));
	while (*env) {
		char **_env = env;
		//dkprintf("%s\n", args_envs + p->args_len + (unsigned long)*env);
		*env = (char *)addr + p->args_len + (unsigned long)*env;
		env = ++_env;
	}
	env = (char **)(args_envs + p->args_len + sizeof(int));
	
	dkprintf("env OK\n");

	p->rprocess = (unsigned long)proc;
	p->rpgtable = virt_to_phys(proc->vm->page_table);
	if(init_process_stack(proc, pn, argc, argv, envc, env) != 0){
		goto err;
	}

	dkprintf("new process : %p [%d] / table : %p\n", proc, proc->pid,
	        proc->vm->page_table);

	ihk_mc_free(pn);

	ihk_mc_unmap_virtual(p, npages, 1);
	ihk_mc_unmap_memory(NULL, phys, sz);
	return 0;
err:
	ihk_mc_free(pn);
	ihk_mc_unmap_virtual(p, npages, 1);
	ihk_mc_unmap_memory(NULL, phys, sz);
	free_process_memory(proc);
	destroy_process(proc);
	return -ENOMEM;
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
	lparam->request_pa = ihk_mc_map_memory(NULL, param->request_page,
	                                       REQUEST_PAGE_COUNT * PAGE_SIZE);
	if((lparam->request_va = ihk_mc_map_virtual(lparam->request_pa,
	                                        REQUEST_PAGE_COUNT,
	                                        PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		// TODO: 
		panic("ENOMEM");
	}

	lparam->doorbell_rpa = param->doorbell_page;
	lparam->doorbell_pa = ihk_mc_map_memory(NULL, param->doorbell_page,
	                                        DOORBELL_PAGE_COUNT * 
	                                        PAGE_SIZE);
	if((lparam->doorbell_va = ihk_mc_map_virtual(lparam->doorbell_pa,
	                                         DOORBELL_PAGE_COUNT,
	                                         PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		// TODO: 
		panic("ENOMEM");
	}

	lparam->post_rpa = param->post_page;
	lparam->post_pa = ihk_mc_map_memory(NULL, param->post_page,
	                                    PAGE_SIZE);
	if((lparam->post_va = ihk_mc_map_virtual(lparam->post_pa, 1,
	                                     PTATTR_WRITABLE | PTATTR_FOR_USER)) == NULL){
		// TODO: 
		panic("ENOMEM");
	}

	lparam->post_fin = 1;

	dkprintf("Syscall parameters: (%d)\n", ihk_mc_get_processor_id());
	dkprintf(" Response: %lx, %p\n",
	        lparam->response_pa, lparam->response_va);
	dkprintf(" Request : %lx, %lx, %p\n",
	        lparam->request_pa, lparam->request_rpa, lparam->request_va);
	dkprintf(" Doorbell: %lx, %lx, %p\n",
	        lparam->doorbell_pa, lparam->doorbell_rpa, lparam->doorbell_va);
	dkprintf(" Post: %lx, %lx, %p\n",
	        lparam->post_pa, lparam->post_rpa, lparam->post_va);
}

static void syscall_channel_send(struct ihk_ikc_channel_desc *c,
                                 struct ikc_scd_packet *packet)
{
	ihk_ikc_send(c, packet, 0);
}

static int syscall_packet_handler(struct ihk_ikc_channel_desc *c,
                                  void *__packet, void *ihk_os)
{
	struct ikc_scd_packet *packet = __packet;
	struct ikc_scd_packet pckt;

	switch (packet->msg) {
	case SCD_MSG_INIT_CHANNEL_ACKED:
		dkprintf("SCD_MSG_INIT_CHANNEL_ACKED\n");
		process_msg_init_acked(packet->arg);
		return 0;

	case SCD_MSG_PREPARE_PROCESS:
		if(process_msg_prepare_process(packet->arg) == 0)
			pckt.msg = SCD_MSG_PREPARE_PROCESS_ACKED;
		else
			pckt.msg = SCD_MSG_PREPARE_PROCESS_NACKED;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		syscall_channel_send(c, &pckt);

		return 0;

	case SCD_MSG_SCHEDULE_PROCESS:
		dkprintf("SCD_MSG_SCHEDULE_PROCESS: %lx\n", packet->arg);

		runq_add_proc((struct process *)packet->arg, 
		              ihk_mc_get_processor_id());
					  
		//cpu_local_var(next) = (struct process *)packet->arg;
		return 0;
	}
	return 0;
}

void init_host_syscall_channel(void)
{
	struct ihk_ikc_connect_param param;
	struct ikc_scd_packet pckt;

	param.port = 501;
	param.pkt_size = sizeof(struct ikc_scd_packet);
	param.queue_size = PAGE_SIZE;
	param.magic = 0x1129;
	param.handler = syscall_packet_handler;

	dkprintf("(syscall) Trying to connect host ...");
	while (ihk_ikc_connect(NULL, &param) != 0) {
		dkprintf(".");
		ihk_mc_delay_us(1000 * 1000);
	}
	dkprintf("connected.\n");

	get_this_cpu_local_var()->syscall_channel = param.channel;

	process_msg_init(&cpu_local_var(iip));
	pckt.msg = SCD_MSG_INIT_CHANNEL;
	pckt.ref = ihk_mc_get_processor_id();
	pckt.arg = virt_to_phys(&cpu_local_var(iip));
	syscall_channel_send(param.channel, &pckt);
}
