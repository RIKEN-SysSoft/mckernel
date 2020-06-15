struct tof_core_cq {
	union {
		char whole_struct[264];
		struct {
			char padding0[56];
			#include "tof_core_cq_reg.h"
		};
	};
};
