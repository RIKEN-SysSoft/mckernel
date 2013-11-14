/**
 * \file dma.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare types and functions for DMA.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_GENERIC_INCLUDE_DMA_H
#define __HEADER_GENERIC_INCLUDE_DMA_H

#include <ihk/ikc.h>

struct ihk_dma_request {
	ihk_os_t src_os;
	unsigned long src_phys;
	ihk_os_t dest_os;
	unsigned long dest_phys;
	unsigned long size;
	
	void (*callback)(void *);
	void *priv;
	ihk_os_t notify_os;
	unsigned long *notify;
};

int ihk_mc_dma_request(int channel, struct ihk_dma_request *req);

#endif
