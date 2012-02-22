#ifndef INIT_H
#define INIT_H

extern void arch_init(void);
extern void kmsg_init(void);
extern void mem_init(void);
extern void ikc_master_init(void);
extern void ap_init(void);
extern void arch_ready(void);
extern void mc_ikc_init(void);
extern void cpu_local_var_init(void);
extern void kmalloc_init(void);
extern void ap_start(void);
extern void aal_mc_dma_init(void);
extern void init_host_syscall_channel(void);
extern void sched_init(void);
extern void pc_ap_init(void);

#endif
