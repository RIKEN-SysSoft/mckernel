#include <unistd.h>

#define __unused __attribute__((unused))

static __unused int data[1024*1024] = { 1, 0 };
static __unused int data_zero[1024*1024] = { 0 };
static __unused int const data_ro[1024*1024] = { 1, 0 };
static __unused int const data_ro_zero[1024*1024] = { 0 };

int main(int argc, char *argv[])
{
	return 0;
}
