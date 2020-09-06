struct tof_utofu_bg {
	union {
		char whole_struct[160];
		struct {
			char padding0[0];
			struct tof_utofu_device common;
		};
		struct {
			char padding1[80];
			uint8_t tni;
		};
		struct {
			char padding2[81];
			uint8_t bgid;
		};
		struct {
			char padding3[88];
			#include "tof_utofu_bg_bch.h"
		};
	};
};
