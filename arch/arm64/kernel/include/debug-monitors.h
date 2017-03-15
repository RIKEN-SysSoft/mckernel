/* debug-monitors.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_COMMON_DEBUG_MONITORS_H
#define __HEADER_ARM64_COMMON_DEBUG_MONITORS_H

/* Low-level stepping controls. */
#define DBG_MDSCR_SS		(1 << 0)
#define DBG_SPSR_SS		(1 << 21)

/* MDSCR_EL1 enabling bits */
#define DBG_MDSCR_KDE		(1 << 13)
#define DBG_MDSCR_MDE		(1 << 15)
#define DBG_MDSCR_MASK		~(DBG_MDSCR_KDE | DBG_MDSCR_MDE)

#define DBG_ESR_EVT(x)		(((x) >> 27) & 0x7)

/* AArch64 */
#define DBG_ESR_EVT_HWBP	0x0
#define DBG_ESR_EVT_HWSS	0x1
#define DBG_ESR_EVT_HWWP	0x2
#define DBG_ESR_EVT_BRK		0x6

#ifndef __ASSEMBLY__

unsigned char debug_monitors_arch(void);
void mdscr_write(unsigned int mdscr);
unsigned int mdscr_read(void);
void debug_monitors_init(void);

struct pt_regs;
void set_regs_spsr_ss(struct pt_regs *regs);
void clear_regs_spsr_ss(struct pt_regs *regs);

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_DEBUG_MONITORS_H */
