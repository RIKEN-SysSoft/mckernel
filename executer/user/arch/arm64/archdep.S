/* archdep.S COPYRIGHT FUJITSU LIMITED 2017 */

#include <sys/syscall.h>

/*
 * int switch_ctx(int fd, unsigned long cmd, void **param, void *lctx,
 *		  void *rctx);
 *   <register> : <argument>
 *     x0 : int fd
 *     x1 : unsigned long cmd
 *     x2 : void **param
 *     x3 : void *lctx
 *     x4 : void *rctx
 */
.global switch_ctx
switch_ctx:
	/* send ioctl(fd, cmd, param) */
	mov	w8, #__NR_ioctl
	svc	#0x0

	/* if (syscall_ret < 0 && -4095(-MAX_ERRNO) <= syscall_ret) goto 1f; */
	cmp	x0, #0xfffffffffffff000
	b.hi	1f

	/* if (syscall_ret != 0) goto 2f; */
	cmp	x0, #0x0
	b.ne	2f

	/* function_ret = 0 */
	mov	x0, #0x0
	ret

	/* error case */
1:
	/* function_ret = -1 */
	mov	x0, #0xffffffffffffffff
2:
	ret

