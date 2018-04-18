/* arch-timer.h COPYRIGHT FUJITSU LIMITED 2016-2018 */
#ifndef __HEADER_ARM64_COMMON_ARCH_TIMER_H
#define __HEADER_ARM64_COMMON_ARCH_TIMER_H

#include <ihk/cpu.h>

/* @ref.impl include/clocksource/arm_arch_timer.h */
#define ARCH_TIMER_USR_PCT_ACCESS_EN	(1 << 0)	/* physical counter */
#define ARCH_TIMER_USR_VCT_ACCESS_EN	(1 << 1)	/* virtual counter */
#define ARCH_TIMER_VIRT_EVT_EN		(1 << 2)
#define ARCH_TIMER_EVT_TRIGGER_SHIFT	(4)
#define ARCH_TIMER_EVT_TRIGGER_MASK	(0xF << ARCH_TIMER_EVT_TRIGGER_SHIFT)
#define ARCH_TIMER_USR_VT_ACCESS_EN	(1 << 8)	/* virtual timer registers */
#define ARCH_TIMER_USR_PT_ACCESS_EN	(1 << 9)	/* physical timer registers */

/* @ref.impl linux4.10.16 */
/* include/clocksource/arm_arch_timer.h */
#define ARCH_TIMER_CTRL_ENABLE		(1 << 0)
#define ARCH_TIMER_CTRL_IT_MASK		(1 << 1)
#define ARCH_TIMER_CTRL_IT_STAT		(1 << 2)

enum arch_timer_reg {
	ARCH_TIMER_REG_CTRL,
	ARCH_TIMER_REG_TVAL,
};

extern int get_timer_intrid(void);
extern void arch_timer_init(void);
extern struct ihk_mc_interrupt_handler *get_timer_handler(void);

#endif	/* __HEADER_ARM64_COMMON_ARCH_TIMER_H */
