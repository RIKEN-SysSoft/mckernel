#ifndef IHK_CPU_H
#define IHK_CPU_H

#include <list.h>
#include <ihk/context.h>

void cpu_enable_interrupt(void);
void cpu_disable_interrupt(void);
void cpu_halt(void);
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
};

int ihk_mc_get_vector(enum ihk_mc_gv_type type);
int ihk_mc_interrupt_host(int cpu, int vector);

struct ihk_mc_cpu_info {
	int ncpus;
	int *hw_ids;
	int *nodes;
};

struct ihk_mc_cpu_info *ihk_mc_get_cpu_info(void);
void ihk_mc_boot_cpu(int cpuid, unsigned long pc);
int ihk_mc_get_processor_id(void);
int ihk_mc_get_hardware_processor_id(void);

void ihk_mc_delay_us(int us);
void ihk_mc_set_syscall_handler(long (*handler)(int, ihk_mc_user_context_t *));

void ihk_mc_init_ap(void);

void ihk_mc_init_context(ihk_mc_kernel_context_t *new_ctx,
                         void *stack_pointer,
                         void (*next_function)(void));
void ihk_mc_switch_context(ihk_mc_kernel_context_t *old_ctx,
                           ihk_mc_kernel_context_t *new_ctx);
int ihk_mc_interrupt_cpu(int cpu, int vector);

void ihk_mc_init_user_process(ihk_mc_kernel_context_t *ctx,
                              ihk_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long user_pc,
                              unsigned long user_sp);

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

int ihk_mc_arch_set_special_register(enum ihk_asr_type, unsigned long value);
int ihk_mc_arch_get_special_register(enum ihk_asr_type, unsigned long *value);

#endif
