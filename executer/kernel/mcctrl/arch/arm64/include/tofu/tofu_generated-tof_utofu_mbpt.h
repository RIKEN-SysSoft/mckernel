struct tof_utofu_mbpt {
	union {
		char whole_struct[56];
		struct {
			char padding0[0];
			struct kref kref;
		};
		struct {
			char padding1[8];
			struct tof_utofu_cq *ucq;
		};
		struct {
			char padding2[16];
			uintptr_t iova;
		};
		struct {
			char padding3[24];
			struct scatterlist *sg;
		};
		struct {
			char padding4[32];
			size_t nsgents;
		};
		struct {
			char padding5[40];
			uintptr_t mbptstart;
		};
		struct {
			char padding6[48];
			size_t pgsz;
		};
	};
};
