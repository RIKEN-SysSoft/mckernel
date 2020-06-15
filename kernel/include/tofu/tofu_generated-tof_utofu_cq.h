struct tof_utofu_cq {
	union {
		char whole_struct[384];
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
			uint8_t cqid;
		};
		struct {
			char padding3[104];
			#include "tof_utofu_cq_trans.h"
		};
		struct {
			char padding4[128];
			struct tof_icc_steering_entry *steering;
		};
		struct {
			char padding5[136];
			struct tof_icc_mb_entry *mb;
		};
		struct {
			char padding6[186];
			uint8_t num_stag;
		};
	};
};
