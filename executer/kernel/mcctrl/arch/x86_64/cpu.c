/* This is copy of the necessary part from McKernel, for uti-futex */

#include <cpu.h>

/*@
  @ assigns \nothing;
  @ behavior to_enabled:
  @   assumes flags & RFLAGS_IF;
  @   ensures \interrupt_disabled == 0;
  @ behavior to_disabled:
  @   assumes !(flags & RFLAGS_IF);
  @   ensures \interrupt_disabled > 0;
  @*/
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile("push %0; popf" : : "g"(flags) : "memory", "cc");
}

void cpu_pause(void)
{
	asm volatile("pause" ::: "memory");
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled > 0;
  @ behavior from_enabled:
  @   assumes \interrupt_disabled == 0;
  @   ensures \result & RFLAGS_IF;
  @ behavior from_disabled:
  @   assumes \interrupt_disabled > 0;
  @   ensures !(\result & RFLAGS_IF);
  @*/
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile("pushf; pop %0; cli" : "=r"(flags) : : "memory", "cc");

	return flags;
}

unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile("pushf; pop %0; sti" : "=r"(flags) : : "memory", "cc");

	return flags;
}

