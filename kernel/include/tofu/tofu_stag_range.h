#ifndef __TOFU_STAG_RANGE_HEADER__
#define __TOFU_STAG_RANGE_HEADER__

struct tof_utofu_cq;

struct tofu_stag_range {
	uintptr_t start, end;
	int stag;
	struct tof_utofu_cq *ucq;
	struct list_head list; // per-vm_range list
	struct list_head hash; // per-process stag hash
};

#endif // __TOFU_STAG_RANGE_HEADER__

