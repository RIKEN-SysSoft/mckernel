/*
function call convention
rdi, rsi, rdx, rcx, r8, r9: 	IN	arguments
rax:				OUT	return value

syscall convention:
rax:				IN	syscall number
rdi, rsi, rdx, r10, r8, r9:	IN	arguments
rax:				OUT	return value
rcx, r11:			CLOBBER
*/
long uti_syscall6(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
	long ret;
	asm volatile ("movq %[arg3],%%r10; movq %[arg4],%%r8; movq %[arg5],%%r9; syscall"
				  : "=a" (ret)
				  : "a" (syscall_number),
					"D" (arg0), "S" (arg1), "d" (arg2),
					[arg3] "g" (arg3), [arg4] "g" (arg4), [arg5] "g" (arg5)
				  : "rcx", "r11", "r10", "r8", "r9", "memory");
	return ret;
}

long uti_syscall3(long syscall_number, long arg0, long arg1, long arg2)
{
	long ret;
	asm volatile ("syscall"
				  : "=a" (ret)
				  : "a" (syscall_number), "D" (arg0), "S" (arg1), "d" (arg2)
				  : "rcx", "r11", "memory");
	return ret;
}

long uti_syscall1(long syscall_number, long arg0)
{
	long ret;
	asm volatile ("syscall"
				  : "=a" (ret)
				  : "a" (syscall_number), "D" (arg0)
				  : "rcx", "r11", "memory");
	return ret;
}

long uti_syscall0(long syscall_number)
{
	long ret;
	asm volatile ("syscall"
				  : "=a" (ret)
				  : "a" (syscall_number)
				  : "rcx", "r11", "memory");
	return ret;
}
