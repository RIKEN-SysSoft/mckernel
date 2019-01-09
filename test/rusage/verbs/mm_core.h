#ifndef MM_CORE_H_
#define MM_CORE_H_

#include "mtype.h"

//4kB
#define MIC_PAGE_SIZE 4096

int mm_core_read(addr_t offset, int size, void *buf);
int mm_core_write(addr_t offset, int size, void *buf);

#endif /* MM_CORE_H_ */
