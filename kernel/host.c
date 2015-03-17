/**
 * \file host.c
 *  License details are found in the file LICENSE.
 * \brief
 *  host call handlers
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * 	Copyright (C) 2012  RIKEN AICS
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

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
#include <mman.h>
#include <init.h>

//#define DEBUG_PRINT_HOST

#ifdef DEBUG_PRINT_HOST
#define dkprintf kprintf
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
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
 * Prepares the process ranges based on the ELF header described 
 * in program_load_desc and updates physical address in "p" so that
 * host can copy program image.
 * It also prepares args, envs and the process stack.
 * 
 * NOTE: if args, args_len, envs, envs_len are zero, 
 * the function constructs them based on the descriptor 
 */
int prepare_process_ranges_args_envs(struct process *proc, 
		struct program_load_desc *pn,
		struct program_load_desc *p,
		enum ihk_mc_pt_attribute attr,
		char *args, int args_len,
		char *envs, int envs_len) 
{
	char *args_envs, *args_envs_r;
	unsigned long args_envs_p, args_envs_rp;
	unsigned long s, e, up;
	char **argv;
	int i, n, argc, envc, args_envs_npages;
	char **env;
	int range_npages;
	void *up_v;
	unsigned long addr;
	unsigned long flags;
	uintptr_t interp_obase = -1;
	uintptr_t interp_nbase = -1;
	
	n = p->num_sections;

	for (i = 0; i < n; i++) {
		
		if (pn->sections[i].interp && (interp_nbase == (uintptr_t)-1)) {
			interp_obase = pn->sections[i].vaddr;
			interp_obase -= (interp_obase % pn->interp_align);
			interp_nbase = proc->vm->region.map_start;
			interp_nbase = (interp_nbase + pn->interp_align - 1)
				& ~(pn->interp_align - 1);
		}

		if (pn->sections[i].interp) {
			pn->sections[i].vaddr -= interp_obase;
			pn->sections[i].vaddr += interp_nbase;
			p->sections[i].vaddr = pn->sections[i].vaddr;
		}
		s = (pn->sections[i].vaddr) & PAGE_MASK;
		e = (pn->sections[i].vaddr + pn->sections[i].len
				+ PAGE_SIZE - 1) & PAGE_MASK;
		range_npages = (e - s) >> PAGE_SHIFT;
		flags = VR_NONE;
		flags |= PROT_TO_VR_FLAG(pn->sections[i].prot);
		flags |= VRFLAG_PROT_TO_MAXPROT(flags);

		if ((up_v = ihk_mc_alloc_pages(range_npages, IHK_MC_AP_NOWAIT)) 
				== NULL) {
			kprintf("ERROR: alloc pages for ELF section %i\n", i);
			goto err;
		} 
		
		up = virt_to_phys(up_v);
		if (add_process_memory_range(proc, s, e, up, flags, NULL, 0) != 0) {
			ihk_mc_free_pages(up_v, range_npages);
			kprintf("ERROR: adding memory range for ELF section %i\n", i);
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
			dkprintf("0x%lX -> 0x%lX is physically contigous\n", s, e);
		}

		p->sections[i].remote_pa = up;

		/* TODO: Maybe we need flag */
		if (pn->sections[i].interp) {
			proc->vm->region.map_end = e;
		}
		else if (i == 0) {
			proc->vm->region.text_start = s;
			proc->vm->region.text_end = e;
		} 
		else if (i == 1) {
			proc->vm->region.data_start = s;
			proc->vm->region.data_end = e;
		} 
		else {
			proc->vm->region.data_start =
				(s < proc->vm->region.data_start ? 
				 s : proc->vm->region.data_start);
			proc->vm->region.data_end = 
				(e > proc->vm->region.data_end ? 
				 e : proc->vm->region.data_end);
		}
	}

	if (interp_nbase != (uintptr_t)-1) {
		pn->entry -= interp_obase;
		pn->entry += interp_nbase;
		p->entry = pn->entry;
		ihk_mc_modify_user_context(proc->uctx, IHK_UCR_PROGRAM_COUNTER, 
				pn->entry);
	}

	proc->vm->region.brk_start = proc->vm->region.brk_end =
		proc->vm->region.data_end;

	/* Map, copy and update args and envs */
	flags = VR_PROT_READ | VR_PROT_WRITE;
	flags |= VRFLAG_PROT_TO_MAXPROT(flags);
	addr = proc->vm->region.map_start - PAGE_SIZE * SCD_RESERVED_COUNT;
	e = addr + PAGE_SIZE * ARGENV_PAGE_COUNT;

	if((args_envs = ihk_mc_alloc_pages(ARGENV_PAGE_COUNT, IHK_MC_AP_NOWAIT)) == NULL){
		kprintf("ERROR: allocating pages for args/envs\n");
		goto err;
	}
	args_envs_p = virt_to_phys(args_envs);

	if(add_process_memory_range(proc, addr, e, args_envs_p,
				flags, NULL, 0) != 0){
		ihk_mc_free_pages(args_envs, ARGENV_PAGE_COUNT);
		kprintf("ERROR: adding memory range for args/envs\n");
		goto err;
	}

	dkprintf("args_envs mapping\n");

	dkprintf("args: 0x%lX, args_len: %d\n", p->args, p->args_len);

	/* Only map remote address if it wasn't specified as an argument */
	if (!args) {
		// Map in remote physical addr of args and copy it
		args_envs_npages = (p->args_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		dkprintf("args_envs_npages: %d\n", args_envs_npages);
		args_envs_rp = ihk_mc_map_memory(NULL, 
				(unsigned long)p->args, p->args_len);

		dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
		if ((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, 
						args_envs_npages, attr)) == NULL){
			goto err;
		}
		dkprintf("args_envs_r: 0x%lX\n", args_envs_r);
	}
	else {
		args_envs_r = args;
		p->args_len = args_len;
	}

	dkprintf("args copy, nr: %d\n", *((int*)args_envs_r));

	memcpy_long(args_envs, args_envs_r, p->args_len + 8);

	/* Only unmap remote address if it wasn't specified as an argument */
	if (!args) {
		ihk_mc_unmap_virtual(args_envs_r, args_envs_npages, 0);
		ihk_mc_unmap_memory(NULL, args_envs_rp, p->args_len);
	}
	flush_tlb();

	dkprintf("envs: 0x%lX, envs_len: %d\n", p->envs, p->envs_len);

	/* Only map remote address if it wasn't specified as an argument */
	if (!envs) {
		// Map in remote physical addr of envs and copy it after args
		args_envs_npages = (p->envs_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		dkprintf("args_envs_npages: %d\n", args_envs_npages);
		args_envs_rp = ihk_mc_map_memory(NULL, (unsigned long)p->envs, 
				p->envs_len);

		dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
		
		if ((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, 
						args_envs_npages, attr)) == NULL) {
			goto err;
		}
		dkprintf("args_envs_r: 0x%lX\n", args_envs_r);
	}
	else {
		args_envs_r = envs;
		p->envs_len = envs_len;
	}

	dkprintf("envs copy, nr: %d\n", *((int*)args_envs_r));

	memcpy_long(args_envs + p->args_len, args_envs_r, p->envs_len + 8);

	/* Only map remote address if it wasn't specified as an argument */
	if (!envs) {
		ihk_mc_unmap_virtual(args_envs_r, args_envs_npages, 0);
		ihk_mc_unmap_memory(NULL, args_envs_rp, p->envs_len);
	}
	flush_tlb();

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
	
	if (init_process_stack(proc, pn, argc, argv, envc, env) != 0) {
		goto err;
	}

	return 0;

err:
	/* TODO: cleanup allocated ranges */
	return -1;
}

/*
 * Communication with host 
 */
static int process_msg_prepare_process(unsigned long rphys)
{
	unsigned long phys, sz;
	struct program_load_desc *p, *pn;
	int npages, n;
	struct process *proc;
	enum ihk_mc_pt_attribute attr;

	attr = PTATTR_NO_EXECUTE | PTATTR_WRITABLE | PTATTR_FOR_USER;

	sz = sizeof(struct program_load_desc)
		+ sizeof(struct program_image_section) * 16;
	npages = ((rphys + sz - 1) >> PAGE_SHIFT) - (rphys >> PAGE_SHIFT) + 1;

	phys = ihk_mc_map_memory(NULL, rphys, sz);
	if((p = ihk_mc_map_virtual(phys, npages, attr)) == NULL){
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
	proc->ftn->pid = pn->pid;
	proc->ftn->pgid = pn->pgid;
	proc->ftn->ruid = pn->ruid;
	proc->ftn->euid = pn->euid;
	proc->ftn->suid = pn->suid;
	proc->vm->region.user_start = pn->user_start;
	proc->vm->region.user_end = pn->user_end;
	proc->vm->region.map_start = (USER_END / 3) & LARGE_PAGE_MASK;
	proc->vm->region.map_end = proc->vm->region.map_start;
	memcpy(proc->rlimit, pn->rlimit, sizeof(struct rlimit) * MCK_RLIM_MAX);

	/* TODO: Clear it at the proper timing */
	cpu_local_var(scp).post_idx = 0;

	if (prepare_process_ranges_args_envs(proc, pn, p, attr, 
				NULL, 0, NULL, 0) != 0) {
		kprintf("error: preparing process ranges, args, envs, stack\n");
		goto err;
	}

	dkprintf("new process : %p [%d] / table : %p\n", proc, proc->ftn->pid,
	        proc->vm->page_table);

	ihk_mc_free(pn);

	ihk_mc_unmap_virtual(p, npages, 1);
	ihk_mc_unmap_memory(NULL, phys, sz);
	flush_tlb();
	return 0;
err:
	ihk_mc_free(pn);
	ihk_mc_unmap_virtual(p, npages, 1);
	ihk_mc_unmap_memory(NULL, phys, sz);
	free_process_memory(proc);
	destroy_process(proc);
	return -ENOMEM;
}

static void process_msg_init(struct ikc_scd_init_param *pcp, struct syscall_params *lparam)
{
	lparam->response_va = allocate_pages(RESPONSE_PAGE_COUNT, 0);
	lparam->response_pa = virt_to_phys(lparam->response_va);

	pcp->request_page = 0;
	pcp->doorbell_page = 0;
	pcp->response_page = lparam->response_pa;
}

static void process_msg_init_acked(struct ihk_ikc_channel_desc *c, unsigned long pphys)
{
	struct ikc_scd_init_param *param = (void *)pphys;
	struct syscall_params *lparam;
	enum ihk_mc_pt_attribute attr;

	attr = PTATTR_NO_EXECUTE | PTATTR_WRITABLE | PTATTR_FOR_USER;

	lparam = &cpu_local_var(scp);
	if(cpu_local_var(syscall_channel2) == c)
		lparam = &cpu_local_var(scp2);
	lparam->request_rpa = param->request_page;
	lparam->request_pa = ihk_mc_map_memory(NULL, param->request_page,
	                                       REQUEST_PAGE_COUNT * PAGE_SIZE);
	if((lparam->request_va = ihk_mc_map_virtual(lparam->request_pa,
	                                        REQUEST_PAGE_COUNT,
	                                        attr)) == NULL){
		// TODO: 
		panic("ENOMEM");
	}

	lparam->doorbell_rpa = param->doorbell_page;
	lparam->doorbell_pa = ihk_mc_map_memory(NULL, param->doorbell_page,
	                                        DOORBELL_PAGE_COUNT * 
	                                        PAGE_SIZE);
	if((lparam->doorbell_va = ihk_mc_map_virtual(lparam->doorbell_pa,
	                                         DOORBELL_PAGE_COUNT,
	                                         attr)) == NULL){
		// TODO: 
		panic("ENOMEM");
	}

	lparam->post_rpa = param->post_page;
	lparam->post_pa = ihk_mc_map_memory(NULL, param->post_page,
	                                    PAGE_SIZE);
	if((lparam->post_va = ihk_mc_map_virtual(lparam->post_pa, 1,
	                                     attr)) == NULL){
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

extern unsigned long do_kill(int, int, int, struct siginfo *, int ptracecont);
extern void settid(struct process *proc, int mode, int newcpuid, int oldcpuid);

extern void process_procfs_request(unsigned long rarg);
extern int memcheckall();
extern int freecheck(int runcount);
extern int runcount;
extern void terminate_host(int pid);
extern void debug_log(long);

static int syscall_packet_handler(struct ihk_ikc_channel_desc *c,
                                  void *__packet, void *ihk_os)
{
	struct ikc_scd_packet *packet = __packet;
	struct ikc_scd_packet pckt;
	int rc;
	struct process *proc;
	struct mcctrl_signal {
		int	cond;
		int	sig;
		int	pid;
		int	tid;
		struct siginfo	info;
	} *sp, info;
	unsigned long pp;
	int cpuid;

	switch (packet->msg) {
	case SCD_MSG_INIT_CHANNEL_ACKED:
		dkprintf("SCD_MSG_INIT_CHANNEL_ACKED\n");
		process_msg_init_acked(c, packet->arg);
		return 0;

	case SCD_MSG_PREPARE_PROCESS:

		if (find_command_line("memdebug")) {
			memcheckall();
			if (runcount)
				freecheck(runcount);
			runcount++;
		}

		if((rc = process_msg_prepare_process(packet->arg)) == 0){
			pckt.msg = SCD_MSG_PREPARE_PROCESS_ACKED;
			pckt.err = 0;
		}
		else{
			pckt.msg = SCD_MSG_PREPARE_PROCESS_NACKED;
			pckt.err = rc;
		}
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		syscall_channel_send(c, &pckt);

		return 0;

	case SCD_MSG_SCHEDULE_PROCESS:
		cpuid = obtain_clone_cpuid();
		if(cpuid == -1){
			kprintf("No CPU available\n");
			return -1;
		}
		dkprintf("SCD_MSG_SCHEDULE_PROCESS: %lx\n", packet->arg);
		proc = (struct process *)packet->arg;

		settid(proc, 0, cpuid, -1);
		proc->ftn->status = PS_RUNNING;
		runq_add_proc(proc, cpuid);
					  
		//cpu_local_var(next) = (struct process *)packet->arg;
		return 0;
	case SCD_MSG_SEND_SIGNAL:
		pp = ihk_mc_map_memory(NULL, packet->arg, sizeof(struct mcctrl_signal));
		sp = (struct mcctrl_signal *)ihk_mc_map_virtual(pp, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);
		memcpy(&info, sp, sizeof(struct mcctrl_signal));
		ihk_mc_unmap_virtual(sp, 1, 0);
		ihk_mc_unmap_memory(NULL, pp, sizeof(struct mcctrl_signal));
		pckt.msg = SCD_MSG_SEND_SIGNAL;
		pckt.err = 0;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		syscall_channel_send(c, &pckt);

		rc = do_kill(info.pid, info.tid, info.sig, &info.info, 0);
		kprintf("SCD_MSG_SEND_SIGNAL: do_kill(pid=%d, tid=%d, sig=%d)=%d\n", info.pid, info.tid, info.sig, rc);
		return 0;
	case SCD_MSG_PROCFS_REQUEST:
		process_procfs_request(packet->arg);
		return 0;
	case SCD_MSG_CLEANUP_PROCESS:
		dkprintf("SCD_MSG_CLEANUP_PROCESS pid=%d\n", packet->pid);
		terminate_host(packet->pid);
		return 0;
	case SCD_MSG_DEBUG_LOG:
		dkprintf("SCD_MSG_DEBUG_LOG code=%lx\n", packet->arg);
		debug_log(packet->arg);
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

	process_msg_init(&cpu_local_var(iip), &cpu_local_var(scp));
	pckt.msg = SCD_MSG_INIT_CHANNEL;
	pckt.ref = ihk_mc_get_processor_id();
	pckt.arg = virt_to_phys(&cpu_local_var(iip));
	syscall_channel_send(param.channel, &pckt);
}

void init_host_syscall_channel2(void)
{
	struct ihk_ikc_connect_param param;
	struct ikc_scd_packet pckt;

	param.port = 502;
	param.pkt_size = sizeof(struct ikc_scd_packet);
	param.queue_size = PAGE_SIZE;
	param.magic = 0x1329;
	param.handler = syscall_packet_handler;

	dkprintf("(syscall) Trying to connect host ...");
	while (ihk_ikc_connect(NULL, &param) != 0) {
		dkprintf(".");
		ihk_mc_delay_us(1000 * 1000);
	}
	dkprintf("connected.\n");

	get_this_cpu_local_var()->syscall_channel2 = param.channel;

	process_msg_init(&cpu_local_var(iip2), &cpu_local_var(scp2));
	pckt.msg = SCD_MSG_INIT_CHANNEL;
	pckt.ref = ihk_mc_get_processor_id();
	pckt.arg = virt_to_phys(&cpu_local_var(iip2));
	syscall_channel_send(param.channel, &pckt);
}
