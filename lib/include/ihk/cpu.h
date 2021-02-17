/**
 * \file cpu.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare types and functions to control CPU. 
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */
/* cpu.h COPYRIGHT FUJITSU LIMITED 2015-2019 */

#ifndef IHK_CPU_H
#define IHK_CPU_H

#include <list.h>
#include <ihk/context.h>
#include <arch/cpu.h>
#include <mc_perf_event.h>

extern int num_processors;

void cpu_enable_interrupt(void);
void cpu_disable_interrupt(void);
void cpu_halt(void);
void cpu_safe_halt(void);
void cpu_restore_interrupt(unsigned long);
void cpu_pause(void);

unsigned long cpu_disable_interrupt_save(void);
unsigned long cpu_enable_interrupt_save(void);

struct ihk_mc_interrupt_handler {
	struct list_head list;
	void (*func)(void *);
	void *priv;
};
int ihk_mc_register_interrupt_handler(int vector,
                                      struct ihk_mc_interrupt_handler *h);
int ihk_mc_unregister_interrupt_handler(int vector,
                                        struct ihk_mc_interrupt_handler *h);

enum ihk_mc_gv_type {
	IHK_GV_IKC = 1,
	IHK_GV_QUERY_FREE_MEM = 2
};

int ihk_mc_get_vector(enum ihk_mc_gv_type type);
int ihk_mc_interrupt_host(int cpu, int vector);

struct ihk_mc_cpu_info {
	int ncpus;
	int *hw_ids;
	int *nodes;
	int *linux_cpu_ids;
	int *ikc_cpus;
};

struct ihk_mc_cpu_info *ihk_mc_get_cpu_info(void);
void ihk_mc_boot_cpu(int cpuid, unsigned long pc);
int ihk_mc_get_processor_id(void);
int ihk_mc_get_hardware_processor_id(void);
int ihk_mc_get_numa_id(void);
int ihk_mc_get_nr_cores(void);
int ihk_mc_get_nr_linux_cores(void);
int ihk_mc_get_osnum(void);
int ihk_mc_get_core(int id, unsigned long *linux_core_id, unsigned long *apic_id,
                    int *numa_id);
int ihk_mc_get_ikc_cpu(int id);
int ihk_mc_get_apicid(int linux_core_id);

void ihk_mc_delay_us(int us);
void ihk_mc_set_syscall_handler(long (*handler)(int, ihk_mc_user_context_t *));

void ihk_mc_init_ap(void);

void ihk_mc_init_context(ihk_mc_kernel_context_t *new_ctx,
                         void *stack_pointer,
                         void (*next_function)(void));
void *ihk_mc_get_linux_kernel_pgt(void);

int ihk_mc_get_extra_reg_id(unsigned long hw_config, unsigned long hw_config_ext);
unsigned int ihk_mc_get_nr_extra_regs(void);
int ihk_mc_get_extra_reg_idx(int id);
unsigned int ihk_mc_get_extra_reg_msr(int id);
unsigned long ihk_mc_get_extra_reg_event(int id);
unsigned long ihk_mc_hw_event_map(unsigned long hw_event);
unsigned long ihk_mc_hw_cache_event_map(unsigned long hw_cache_event);
unsigned long ihk_mc_hw_cache_extra_reg_map(unsigned long hw_cache_event);
unsigned long ihk_mc_raw_event_map(unsigned long raw_event);
int ihk_mc_validate_event(unsigned long hw_config);
int hw_perf_event_init(struct mc_perf_event *event);
int ihk_mc_event_set_period(struct mc_perf_event *event);
uint64_t ihk_mc_event_update(struct mc_perf_event *event);

static inline int is_sampling_event(struct mc_perf_event *event)
{
	return event->attr.sample_period != 0;
}

/* returns the 'prev' argument of the call that caused the switch to the context returned. */
void *ihk_mc_switch_context(ihk_mc_kernel_context_t *old_ctx,
                           ihk_mc_kernel_context_t *new_ctx,
			   void *prev);
int ihk_mc_interrupt_cpu(int cpu, int vector);

void ihk_mc_init_user_process(ihk_mc_kernel_context_t *ctx,
                              ihk_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long user_pc,
                              unsigned long user_sp);

void ihk_mc_init_user_tlsbase(ihk_mc_user_context_t *ctx,
                              unsigned long tls_base_addr);

#ifdef POSTK_DEBUG_ARCH_DEP_42 /* /proc/cpuinfo support added. */
long ihk_mc_show_cpuinfo(char *buf, size_t buf_size, unsigned long read_off, int *eofp);
#endif /* POSTK_DEBUG_ARCH_DEP_42 */

enum ihk_mc_user_context_regtype {
	IHK_UCR_STACK_POINTER = 1,
	IHK_UCR_PROGRAM_COUNTER = 2,
};

struct thread;
void arch_clone_thread(struct thread *othread, unsigned long pc,
			unsigned long sp, struct thread *nthread);

void ihk_mc_modify_user_context(ihk_mc_user_context_t *uctx,
                                enum ihk_mc_user_context_regtype reg,
                                unsigned long value);

void ihk_mc_debug_show_interrupt_context(const void *reg);

enum ihk_asr_type {
	IHK_ASR_X86_FS,
	IHK_ASR_X86_GS,
};

#define IHK_TLB_FLUSH_IRQ_VECTOR_START		68
#define IHK_TLB_FLUSH_IRQ_VECTOR_SIZE		64
#define IHK_TLB_FLUSH_IRQ_VECTOR_END		(IHK_TLB_FLUSH_IRQ_VECTOR_START + IHK_TLB_FLUSH_IRQ_VECTOR_SIZE)

int ihk_mc_arch_set_special_register(enum ihk_asr_type, unsigned long value);
int ihk_mc_arch_get_special_register(enum ihk_asr_type, unsigned long *value);

extern unsigned int ihk_ikc_irq;
extern unsigned int ihk_ikc_irq_apicid;

extern int gettime_local_support;

void init_tick(void);
void init_delay(void);
void sync_tick(void);

struct pvclock_vsyscall_time_info {
	long contents[64/sizeof(long)];
};

extern struct pvclock_vsyscall_time_info *pvti;
extern int pvti_npages;

int arch_setup_pvclock(void);
void arch_start_pvclock(void);

struct cpu_mapping;
int arch_get_cpu_mapping(struct cpu_mapping **buf, int *nelemsp);
int ihk_mc_ikc_arch_issue_host_ipi(int cpu, int vector);

void smp_func_call_handler(void);
int ihk_mc_get_smp_handler_irq(void);

#endif
