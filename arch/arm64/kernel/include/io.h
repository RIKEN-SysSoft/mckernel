/* io.h COPYRIGHT FUJITSU LIMITED 2015 */
/*
 * Based on arch/arm/include/asm/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_IO_H
#define __ASM_IO_H

#include <ihk/types.h>

#ifdef __KERNEL__

/*
 * Generic IO read/write.  These perform native-endian accesses.
 */
static inline void __raw_writeb(uint8_t val, volatile void *addr)
{
	asm volatile("strb %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writew(uint16_t val, volatile void *addr)
{
	asm volatile("strh %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writel(uint32_t val, volatile void *addr)
{
	asm volatile("str %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writeq(uint64_t val, volatile void *addr)
{
	asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

static inline uint8_t __raw_readb(const volatile void *addr)
{
	uint8_t val;
	asm volatile("ldarb %w0, [%1]"
		     : "=r" (val) : "r" (addr));
	return val;
}

static inline uint16_t __raw_readw(const volatile void *addr)
{
	uint16_t val;

	asm volatile("ldarh %w0, [%1]"
		     : "=r" (val) : "r" (addr));
	return val;
}

static inline uint32_t __raw_readl(const volatile void *addr)
{
	uint32_t val;
	asm volatile("ldar %w0, [%1]"
		     : "=r" (val) : "r" (addr));
	return val;
}

static inline uint64_t __raw_readq(const volatile void *addr)
{
	uint64_t val;
	asm volatile("ldar %0, [%1]"
		     : "=r" (val) : "r" (addr));
	return val;
}

/* IO barriers */
#define __iormb()		rmb()
#define __iowmb()		wmb()

/*
 * Relaxed I/O memory access primitives. These follow the Device memory
 * ordering rules but do not guarantee any ordering relative to Normal memory
 * accesses.
 */
#define readb_relaxed(c)	({ uint8_t  __v = (uint8_t)__raw_readb(c); __v; })
#define readw_relaxed(c)	({ uint16_t __v = (uint16_t)__raw_readw(c); __v; })
#define readl_relaxed(c)	({ uint32_t __v = (uint32_t)__raw_readl(c); __v; })
#define readq_relaxed(c)	({ uint64_t __v = (uint64_t)__raw_readq(c); __v; })

#define writeb_relaxed(v,c)	((void)__raw_writeb((uint8_t)(v),(c)))
#define writew_relaxed(v,c)	((void)__raw_writew((uint16_t)(v),(c)))
#define writel_relaxed(v,c)	((void)__raw_writel((uint32_t)(v),(c)))
#define writeq_relaxed(v,c)	((void)__raw_writeq((uint64_t)(v),(c)))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#define readb(c)		({ uint8_t  __v = readb_relaxed(c); __iormb(); __v; })
#define readw(c)		({ uint16_t __v = readw_relaxed(c); __iormb(); __v; })
#define readl(c)		({ uint32_t __v = readl_relaxed(c); __iormb(); __v; })
#define readq(c)		({ uint64_t __v = readq_relaxed(c); __iormb(); __v; })

#define writeb(v,c)		({ __iowmb(); writeb_relaxed((v),(c)); })
#define writew(v,c)		({ __iowmb(); writew_relaxed((v),(c)); })
#define writel(v,c)		({ __iowmb(); writel_relaxed((v),(c)); })
#define writeq(v,c)		({ __iowmb(); writeq_relaxed((v),(c)); })

#endif /* __KERNEL__ */
#endif /* __ASM_IO_H */
