#ifndef __HEADER_KMALLOC_H
#define __HEADER_KMALLOC_H

#include <ihk/mm.h>

void *kmalloc(int size, enum ihk_mc_ap_flag flag);
void kfree(void *ptr);

#endif
