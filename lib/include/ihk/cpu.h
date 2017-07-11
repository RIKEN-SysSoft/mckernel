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

#ifndef IHK_CPU_H
#define IHK_CPU_H

#include <list.h>
#include <ihk/context.h>

void cpu_enable_interrupt(void);
void cpu_disable_interrupt(void);
void cpu_halt(void);
void cpu_safe_halt(void);
void cpu_restore_interrupt(unsigned long);
void cpu_pause(void);

#define barrier()   asm volatile("" : : : "memory")

unsigned long cpu_disable_interrupt_save(void);

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
int ihk_mc_get_nr_cores();
int ihk_mc_get_nr_linux_cores();
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

enum ihk_mc_user_context_regtype {
	IHK_UCR_STACK_POINTER = 1,
	IHK_UCR_PROGRAM_COUNTER = 2,
};

void ihk_mc_modify_user_context(ihk_mc_user_context_t *uctx,
                                enum ihk_mc_user_context_regtype reg,
                                unsigned long value);

void ihk_mc_debug_show_interrupt_context(const void *reg);

enum ihk_asr_type {
	IHK_ASR_X86_FS,
	IHK_ASR_X86_GS,
};

/* Local IRQ vectors */
#define LOCAL_TIMER_VECTOR  0xef
#define LOCAL_PERF_VECTOR   0xf0

#define IHK_TLB_FLUSH_IRQ_VECTOR_START		68
#define IHK_TLB_FLUSH_IRQ_VECTOR_SIZE		64
#define IHK_TLB_FLUSH_IRQ_VECTOR_END		(IHK_TLB_FLUSH_IRQ_VECTOR_START + IHK_TLB_FLUSH_IRQ_VECTOR_SIZE)

#define LOCAL_SMP_FUNC_CALL_VECTOR   0xf1

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

#endif
