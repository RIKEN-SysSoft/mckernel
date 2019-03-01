/* archdep_c.c COPYRIGHT FUJITSU LIMITED 2019 */

long uti_syscall6(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
	long ret;
	asm volatile(
		"mov x8, %1;"
		"mov x0, %2;"
		"mov x1, %3;"
		"mov x2, %4;"
		"mov x3, %5;"
		"mov x4, %6;"
		"mov x5, %7;"
		"svc #0x0;"
		"mov %0, x0;"
		: "=r" (ret)
		: "r" (syscall_number),
		  "r" (arg0), "r" (arg1), "r" (arg2),
		  "r" (arg3), "r" (arg4), "r" (arg5));
	return ret;
}

long uti_syscall3(long syscall_number, long arg0, long arg1, long arg2)
{
	long ret;
	asm volatile(
		"mov x8, %1;"
		"mov x0, %2;"
		"mov x1, %3;"
		"mov x2, %4;"
		"svc #0x0;"
		"mov %0, x0;"
		: "=r" (ret)
		: "r" (syscall_number),
		  "r" (arg0), "r" (arg1), "r" (arg2));
	return ret;
}

long uti_syscall1(long syscall_number, long arg0)
{
	long ret;
	asm volatile(
		"mov x8, %1;"
		"mov x0, %2;"
		"svc #0x0;"
		"mov %0, x0;"
		: "=r" (ret)
		: "r" (syscall_number),
		  "r" (arg0));
	return ret;
}

long uti_syscall0(long syscall_number)
{
	long ret;
	asm volatile(
		"mov x8, %1;"
		"svc #0x0;"
		"mov %0, x0;"
		: "=r" (ret)
		: "r" (syscall_number));
	return ret;
}
