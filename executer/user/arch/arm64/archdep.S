/* archdep.S COPYRIGHT FUJITSU LIMITED 2017 */

#include <sys/syscall.h>

/*
 * int switch_ctx(int fd, unsigned long cmd, void **param, void *lctx, void *rctx);
 *   <register> : <argument>
 *     x0 : int fd
 *     x1 : unsigned long cmd
 *     x2 : void **param
 *     x3 : void *lctx
 *     x4 : void *rctx
 */
.global switch_ctx
switch_ctx:
	/* *lctx head 8 bytes zero clear */
	str	xzr, [x3]

	/* save global registers to *lctx */
	stp	x0, x1, [x3, #8 + 16 * 0]
	stp	x2, x3, [x3, #8 + 16 * 1]
	stp	x4, x5, [x3, #8 + 16 * 2]
	stp	x6, x7, [x3, #8 + 16 * 3]
	stp	x8, x9, [x3, #8 + 16 * 4]
	stp	x10, x11, [x3, #8 + 16 * 5]
	stp	x12, x13, [x3, #8 + 16 * 6]
	stp	x14, x15, [x3, #8 + 16 * 7]
	stp	x16, x17, [x3, #8 + 16 * 8]
	stp	x18, x19, [x3, #8 + 16 * 9]
	stp	x20, x21, [x3, #8 + 16 * 10]
	stp	x22, x23, [x3, #8 + 16 * 11]
	stp	x24, x25, [x3, #8 + 16 * 12]
	stp	x26, x27, [x3, #8 + 16 * 13]
	stp	x28, x29, [x3, #8 + 16 * 14]

	/* save stackpointer and return address to *lctx */
	mov	x20, sp
	stp	x20, x30, [x3, #8 + 16 * 15]

	/* save pstate to *lctx */
	mrs	x20, nzcv
	orr	x21, x21, x20
	str	x21, [x3, #8 + 16 * 16]

	/* send ioctl(fd, cmd, param) */
	mov	w8, #__NR_ioctl
	svc	#0x0

	/* if (syscall_ret < 0 && -4095(-MAX_ERRNO) <= syscall_ret) goto 1f; */
	cmp	x0, #0xfffffffffffff000
	b.hi	1f

	/* if (syscall_ret != 0) goto 2f; */
	cmp	x0, #0x0
	b.ne	2f

	/* set tls base address from *rctx */
	ldr	x20, [x4, #8 + 16 * 16 + 8]
	msr	tpidr_el0, x20

	/* restore pstate from *rctx */
	/* currentel is read only */
	ldr	x20, [x4, #8 + 16 * 16]
	msr	nzcv, x20

	/* restore stackpointer and return address from *rctx */
	ldp	x20, x30, [x4, #8 + 16 * 15]
	mov	sp, x20

	/* restore global registers from *rctx */
	ldp	x28, x29, [x4, #8 + 16 * 14]
	ldp	x26, x27, [x4, #8 + 16 * 13]
	ldp	x24, x25, [x4, #8 + 16 * 12]
	ldp	x22, x23, [x4, #8 + 16 * 11]
	ldp	x20, x21, [x4, #8 + 16 * 10]
	ldp	x18, x19, [x4, #8 + 16 * 9]
	ldp	x16, x17, [x4, #8 + 16 * 8]
	ldp	x14, x15, [x4, #8 + 16 * 7]
	ldp	x12, x13, [x4, #8 + 16 * 6]
	ldp	x10, x11, [x4, #8 + 16 * 5]
	ldp	x8, x9, [x4, #8 + 16 * 4]
	ldp	x6, x7, [x4, #8 + 16 * 3]
	ldp	x4, x5, [x4, #8 + 16 * 2]
	ldp	x2, x3, [x4, #8 + 16 * 1]
	ldp	x0, x1, [x4, #8 + 16 * 0]

	/* function_ret = 0 */
	mov	x0, #0x0
	ret

	/* error case */
1:
	/* syscall_ret = -1 */
	mov	x0, #0xffffffffffffffff
2:
	/* restore global registers from *rctx */
	ldp	x28, x29, [x3, #8 + 16 * 14]
	ldp	x26, x27, [x3, #8 + 16 * 13]
	ldp	x24, x25, [x3, #8 + 16 * 12]
	ldp	x22, x23, [x3, #8 + 16 * 11]
	ldp	x20, x21, [x3, #8 + 16 * 10]
	ldp	x18, x19, [x3, #8 + 16 * 9]
	ldp	x16, x17, [x3, #8 + 16 * 8]
	ldp	x14, x15, [x3, #8 + 16 * 7]
	ldp	x12, x13, [x3, #8 + 16 * 6]
	ldp	x10, x11, [x3, #8 + 16 * 5]
	ldp	x8, x9, [x3, #8 + 16 * 4]
	ldp	x6, x7, [x3, #8 + 16 * 3]
	ldp	x4, x5, [x3, #8 + 16 * 2]
	ldp	x2, x3, [x3, #8 + 16 * 1]
	ldr	x1, [x3, #8 + 16 * 0 + 8]

	ret

