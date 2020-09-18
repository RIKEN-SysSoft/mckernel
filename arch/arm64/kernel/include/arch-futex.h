/* arch-futex.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_ARCH_FUTEX_H
#define __HEADER_ARM64_COMMON_ARCH_FUTEX_H


/*
 * @ref.impl 
 * 	linux-linaro/arch/arm64/include/asm/futex.h:__futex_atomic_op
 */
#define ___futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg)		\
do {								\
	asm volatile(							\
"1:	ldxr	%w1, %2\n"						\
	insn "\n"							\
"2:	stlxr	%w3, %w0, %2\n"						\
"	cbnz	%w3, 1b\n"						\
"	dmb	ish\n"							\
"3:\n"									\
"	.pushsection .fixup,\"ax\"\n"					\
"	.align	2\n"							\
"4:	mov	%w0, %w5\n"						\
"	b	3b\n"							\
"	.popsection\n"							\
"	.pushsection __ex_table,\"a\"\n"				\
"	.align	3\n"							\
"	.quad	1b, 4b, 2b, 4b\n"					\
"	.popsection\n"							\
	: "=&r" (ret), "=&r" (oldval), "+Q" (*uaddr), "=&r" (tmp)	\
	: "r" (oparg), "Ir" (-EFAULT)					\
	: "memory");						\
} while (0);

#ifndef IHK_OS_MANYCORE
#include <linux/uaccess.h>

#define __futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg)		\
do {								\
	uaccess_enable();					\
	___futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg)		\
	uaccess_disable();					\
} while (0);

#else
#define __futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg)		\
	___futex_atomic_op(insn, ret, oldval, uaddr, tmp, oparg)		\

#endif

/*
 * @ref.impl 
 * 	linux-linaro/arch/arm64/include/asm/futex.h:futex_atomic_op_inuser
 */
static inline int futex_atomic_op_inuser(int encoded_op,
					 int __user *uaddr)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op & 0x00fff000) >> 12;
	int cmparg = encoded_op & 0xfff;
	int oldval = 0, ret, tmp;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

#ifdef __UACCESS__
	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;
#endif

	// pagefault_disable();	/* implies preempt_disable() */

	switch (op) {
	case FUTEX_OP_SET:
		__futex_atomic_op("mov	%w0, %w4",
				  ret, oldval, uaddr, tmp, oparg);
		break;
	case FUTEX_OP_ADD:
		__futex_atomic_op("add	%w0, %w1, %w4",
				  ret, oldval, uaddr, tmp, oparg);
		break;
	case FUTEX_OP_OR:
		__futex_atomic_op("orr	%w0, %w1, %w4",
				  ret, oldval, uaddr, tmp, oparg);
		break;
	case FUTEX_OP_ANDN:
		__futex_atomic_op("and	%w0, %w1, %w4",
				  ret, oldval, uaddr, tmp, ~oparg);
		break;
	case FUTEX_OP_XOR:
		__futex_atomic_op("eor	%w0, %w1, %w4",
				  ret, oldval, uaddr, tmp, oparg);
		break;
	default:
		ret = -ENOSYS;
	}

	// pagefault_enable();	/* subsumes preempt_enable() */

	if (!ret) {
		switch (cmp) {
		case FUTEX_OP_CMP_EQ: ret = (oldval == cmparg); break;
		case FUTEX_OP_CMP_NE: ret = (oldval != cmparg); break;
		case FUTEX_OP_CMP_LT: ret = (oldval < cmparg); break;
		case FUTEX_OP_CMP_GE: ret = (oldval >= cmparg); break;
		case FUTEX_OP_CMP_LE: ret = (oldval <= cmparg); break;
		case FUTEX_OP_CMP_GT: ret = (oldval > cmparg); break;
		default: ret = -ENOSYS;
		}
	}
	return ret;
}

/*
 * @ref.impl 
 * 	linux-linaro/arch/arm64/include/asm/futex.h:futex_atomic_cmpxchg_inatomic
 * 	mckernel/kernel/include/futex.h:futex_atomic_cmpxchg_inatomic (x86 depend)
 */
static inline int
futex_atomic_cmpxchg_inatomic(int __user *uaddr, int oldval, int newval)
{
	int ret = 0;
	int val, tmp;

	if(uaddr == NULL) {
		return -EFAULT;
	}
#ifdef __UACCESS__
	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int))) {
		return -EFAULT;
	}
#endif

	asm volatile("// futex_atomic_cmpxchg_inatomic\n"
"1:	ldxr	%w1, %2\n"
"	sub	%w3, %w1, %w4\n"
"	cbnz	%w3, 3f\n"
"2:	stlxr	%w3, %w5, %2\n"
"	cbnz	%w3, 1b\n"
"	dmb	ish\n"
"3:\n"
"	.pushsection .fixup,\"ax\"\n"
"4:	mov	%w0, %w6\n"
"	b	3b\n"
"	.popsection\n"
"	.pushsection __ex_table,\"a\"\n"
"	.align	3\n"
"	.quad	1b, 4b, 2b, 4b\n"
"	.popsection\n"
	: "+r" (ret), "=&r" (val), "+Q" (*uaddr), "=&r" (tmp)
	: "r" (oldval), "r" (newval), "Ir" (-EFAULT)
	: "memory");

	return ret;
}

#endif /* !__HEADER_ARM64_COMMON_ARCH_FUTEX_H */
