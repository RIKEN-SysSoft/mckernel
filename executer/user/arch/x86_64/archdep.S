/*
arg: rdi, rsi, rdx, rcx, r8, r9
ret: rax

rax syscall number
syscall: (rax:num) rdi rsi rdx r10 r8 r9 (rcx:ret addr)
fd, cmd, param
rdi: fd
rsi: cmd
rdx: param
rcx: save area
r8: new thread context
*/

.global switch_ctx
switch_ctx:
	movq	$0,0x00(%rcx)
	movq	%rax,0x8(%rcx)
	movq	%rbx,0x10(%rcx)
	movq	%rcx,0x18(%rcx)
	movq	%rdx,0x20(%rcx)
	movq	%rsi,0x28(%rcx)
	movq	%rdi,0x30(%rcx)
	movq	%rbp,0x38(%rcx)
	movq	%r8,0x40(%rcx)
	movq	%r9,0x48(%rcx)
	movq	%r10,0x50(%rcx)
	movq	%r11,0x58(%rcx)
	movq	%r12,0x60(%rcx)
	movq	%r13,0x68(%rcx)
	movq	%r14,0x70(%rcx)
	movq	%r15,0x78(%rcx)
	pushfq
	popq	%rax
	movq	%rax,0x80(%rcx)
	movq	0x00(%rsp),%rax
	movq	%rax,0x88(%rcx)
	movq	%rsp,0x90(%rcx)
	movq	%rcx,%r10

	pushq	%rcx
	pushq	%r8
	pushq	%rax

	mov	$0x10,%eax /* ioctl */
	syscall
3:

	popq	%r8
	popq	%r8
	popq	%rcx

	movq	%r10,%rcx
	cmp	$0xfffffffffffff001,%eax
	jae	1f

	test	%eax,%eax
	jnz	2f

	pushq	%rax
	movq	$158,%rax /* arch_prctl */
	movq	$0x1002,%rdi /* ARCH_SET_FS */
	movq	0x98(%r8),%rsi
	syscall
	popq	%rax

	movq	0x10(%r8),%rbx
	movq	0x18(%r8),%rcx
	movq	0x20(%r8),%rdx
	movq	0x28(%r8),%rsi
	movq	0x30(%r8),%rdi
	movq	0x38(%r8),%rbp
	movq	0x48(%r8),%r9
	movq	0x50(%r8),%r10
	movq	0x58(%r8),%r11
	movq	0x60(%r8),%r12
	movq	0x68(%r8),%r13
	movq	0x70(%r8),%r14
	movq	0x78(%r8),%r15
	movq	0x80(%r8),%rax
	pushq	%rax
	popfq
	movq	0x90(%r8),%rsp
//	movq	0x8(%r8),%rax /* for interrupts */
	movq	0x40(%r8),%r8

	movq	$0,%rax   /* ioctl return */

	pushq	%rcx
	retq

1:
	mov	$0xffffffffffffffff,%eax
2:
	pushq	%rax
	movq	$158,%rax /* arch_prctl */
	movq	$0x1002,%rdi /* ARCH_SET_FS */
	movq	0x98(%rcx),%rsi
	syscall
	popq	%rax

	movq	0x10(%rcx),%rbx
	movq	0x28(%rcx),%rsi
	movq	0x30(%rcx),%rdi
	movq	0x38(%rcx),%rbp
	movq	0x40(%rcx),%r8
	movq	0x48(%rcx),%r9
	movq	0x50(%rcx),%r10
	movq	0x58(%rcx),%r11
	movq	0x60(%rcx),%r12
	movq	0x68(%rcx),%r13
	movq	0x70(%rcx),%r14
	movq	0x78(%rcx),%r15
	movq	0x80(%rcx),%rdx
	pushq	%rdx
	popfq
	movq	0x20(%rcx),%rdx
	movq	0x18(%rcx),%rcx
	retq

/*
arg: rdi, rsi, rdx, rcx, r8, r9
ret: rax
unsigned long
compare_and_swap(unsigned long *addr, unsigned long old, unsigned long new);
rdi: addr
rsi: old
rdx: new
RET: old value
 */
.global compare_and_swap
compare_and_swap:
	movq	%rsi,%rax
	lock
	cmpxchgq	%rdx,0(%rdi)
	retq

/*
unsigned int
compare_and_swap_int(unsigned int *addr, unsigned int old, unsigned int new);
ret: old value
 */
.global compare_and_swap_int
compare_and_swap_int:
	movl	%esi,%eax
	lock
	cmpxchgl	%edx,0(%rdi)
	retq

