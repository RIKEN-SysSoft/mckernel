struct tof_utofu_device {
	union {
		char whole_struct[80];
		struct {
			char padding0[0];
			bool enabled;
		};
	};
};
