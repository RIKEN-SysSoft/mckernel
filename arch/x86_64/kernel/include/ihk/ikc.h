/**
 * \file ikc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare functions to initialize Inter-Kernel Communication
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_X86_COMMON_IHK_IKC_H
#define HEADER_X86_COMMON_IHK_IKC_H

#include <ikc/ihk.h>

#define IKC_PORT_IKC2MCKERNEL 501
#define IKC_PORT_IKC2LINUX    503

/* manycore side */
int ihk_mc_ikc_init_first(struct ihk_ikc_channel_desc *,
                          ihk_ikc_ph_t handler);

#endif

