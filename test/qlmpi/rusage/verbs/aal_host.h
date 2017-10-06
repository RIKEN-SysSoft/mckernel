/*
 * aal_host.h
 *
 *  Created on: 2011/08/09
 *      Author: simin
 */

#ifndef AAL_HOST_H_
#define AAL_HOST_H_

#define MAX_DEVNO 2

extern int aal_host_init();
extern int aal_host_dev_init(int dev_no);
extern void* aal_host_mem_alloc(int dev_no, int size);
extern void aal_host_mem_free(void * addr, int size);
extern int aal_host_dev_exit(int dev_no);
extern int aal_host_exit();
extern void* aal_host_mem_va2pa(int dev_no, void *virtual_addr);

#endif /* AAL_HOST_H_ */
