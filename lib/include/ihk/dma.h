#ifndef __HEADER_GENERIC_INCLUDE_DMA_H
#define __HEADER_GENERIC_INCLUDE_DMA_H

#include <aal/ikc.h>

struct aal_dma_request {
	aal_os_t src_os;
	unsigned long src_phys;
	aal_os_t dest_os;
	unsigned long dest_phys;
	unsigned long size;
	
	void (*callback)(void *);
	void *priv;
	aal_os_t notify_os;
	unsigned long *notify;
};

int aal_mc_dma_request(int channel, struct aal_dma_request *req);

#endif
