struct tof_core_bg {
	union {
		char whole_struct[120];
		struct {
			char padding0[0];
			spinlock_t lock;
		};
		struct {
			char padding1[8];
			#include "tof_core_bg_reg.h"
		};
		struct {
			char padding2[24];
			struct tof_core_irq irq;
		};
		struct {
			char padding3[88];
			tof_core_signal_handler sighandler;
		};
		struct {
			char padding4[104];
			uint64_t subnet;
		};
		struct {
			char padding5[112];
			uint32_t gpid;
		};
	};
};
