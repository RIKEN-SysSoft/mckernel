#ifndef __HEADER_KMALLOC_H
#define __HEADER_KMALLOC_H

#include <aal/mm.h>

void *kmalloc(int size, enum aal_mc_ap_flag flag);
void kfree(void *ptr);

#endif
