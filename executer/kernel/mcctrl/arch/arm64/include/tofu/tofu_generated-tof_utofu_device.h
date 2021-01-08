struct tof_utofu_device {
	union {
		char whole_struct[80];
		struct {
			char padding0[0];
			bool enabled;
		};
		struct {
			char padding1[12];
			uint32_t gpid;
		};
		struct {
			char padding2[24];
			uint64_t subnet;
		};
	};
};
