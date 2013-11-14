/**
 * \file amemcpy.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Wait function for asynchronous memory copy
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef HEADER_AMEMCPY_H
#define HEADER_AMEMCPY_H

#include <ihk/cpu.h>

static void memcpy_async_wait(unsigned long *notify)
{
	while (!*notify) {
		cpu_pause();
	}
}

int memcpy_async(unsigned long dest, unsigned long src,
                 unsigned long len, int wait, unsigned long *notify);

#endif
