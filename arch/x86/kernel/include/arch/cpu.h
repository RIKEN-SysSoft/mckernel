/**
 * \file cpu.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare architecture-dependent types and functions to control CPU.
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com>
 *      Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#ifndef ARCH_CPU_H
#define ARCH_CPU_H

#include <ihk/cpu.h>

static inline void rmb(void)
{
	barrier();
}

static inline void wmb(void)
{
	barrier();
}

#endif /* ARCH_CPU_H */
