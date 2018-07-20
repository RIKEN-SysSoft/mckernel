#ifndef __ARCH_MM_H
#define __ARCH_MM_H

struct process_vm;

static inline void
flush_nfo_tlb()
{
}

static inline void
flush_nfo_tlb_mm(struct process_vm *vm)
{
}

#endif
