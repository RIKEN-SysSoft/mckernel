#include <numa.h>
#include <numaif.h>

#define M_B MPOL_BIND
#define M_D MPOL_DEFAULT

struct mbind_info {
	int offset;
	int size;
	int policy;
};
