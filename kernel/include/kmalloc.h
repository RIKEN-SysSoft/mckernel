/**
 * \file kmalloc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  kmalloc and kfree functions
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef __HEADER_KMALLOC_H
#define __HEADER_KMALLOC_H

#include <ihk/mm.h>

void *kmalloc(int size, enum ihk_mc_ap_flag flag);
void kfree(void *ptr);

#endif
