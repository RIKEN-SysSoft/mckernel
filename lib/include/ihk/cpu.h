#ifndef AAL_CPU_H
#define AAL_CPU_H

#include <list.h>
#include <aal/context.h>

void cpu_enable_interrupt(void);
void cpu_disable_interrupt(void);
void cpu_halt(void);
void cpu_restore_interrupt(unsigned long);
void cpu_pause(void);

#define barrier()   asm volatile("" : : : "memory")

unsigned long cpu_disable_interrupt_save(void);

struct aal_mc_interrupt_handler {
	struct list_head list;
	void (*func)(void *);
	void *priv;
};
int aal_mc_register_interrupt_handler(int vector,
                                      struct aal_mc_interrupt_handler *h);
int aal_mc_unregister_interrupt_handler(int vector,
                                        struct aal_mc_interrupt_handler *h);

enum aal_mc_gv_type {
	AAL_GV_IKC = 1,
};

int aal_mc_get_vector(enum aal_mc_gv_type type);
int aal_mc_interrupt_host(int cpu, int vector);

struct aal_mc_cpu_info {
	int ncpus;
	int *hw_ids;
	int *nodes;
};

struct aal_mc_cpu_info *aal_mc_get_cpu_info(void);
void aal_mc_boot_cpu(int cpuid, unsigned long pc);
int aal_mc_get_processor_id(void);
int aal_mc_get_hardware_processor_id(void);

void aal_mc_delay_us(int us);
void aal_mc_set_syscall_handler(long (*handler)(int, aal_mc_user_context_t *));

void aal_mc_init_ap(void);

void aal_mc_init_context(aal_mc_kernel_context_t *new_ctx,
                         void *stack_pointer,
                         void (*next_function)(void));
void aal_mc_switch_context(aal_mc_kernel_context_t *old_ctx,
                           aal_mc_kernel_context_t *new_ctx);
int aal_mc_interrupt_cpu(int cpu, int vector);

void aal_mc_init_user_process(aal_mc_kernel_context_t *ctx,
                              aal_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long user_pc,
                              unsigned long user_sp);

enum aal_mc_user_context_regtype {
	AAL_UCR_STACK_POINTER = 1,
	AAL_UCR_PROGRAM_COUNTER = 2,
};

void aal_mc_modify_user_context(aal_mc_user_context_t *uctx,
                                enum aal_mc_user_context_regtype reg,
                                unsigned long value);

void aal_mc_debug_show_interrupt_context(const void *reg);

enum aal_asr_type {
	AAL_ASR_X86_FS,
	AAL_ASR_X86_GS,
};

int aal_mc_arch_set_special_register(enum aal_asr_type, unsigned long value);
int aal_mc_arch_get_special_register(enum aal_asr_type, unsigned long *value);

#endif
