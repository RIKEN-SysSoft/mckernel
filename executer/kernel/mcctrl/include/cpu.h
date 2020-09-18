/* This is copy of the necessary part from McKernel, for uti-futex */
#ifndef MC_CPU_H
#define MC_CPU_H

void cpu_restore_interrupt(unsigned long flags);
void cpu_pause(void);
unsigned long cpu_disable_interrupt_save(void);
unsigned long cpu_enable_interrupt_save(void);

#endif
