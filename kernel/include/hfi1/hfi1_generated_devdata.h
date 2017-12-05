struct hfi1_devdata {
	union {
		char whole_struct[7232];
		struct {
			char padding0[2984];
			u8 *kregbase1;
		};
		struct {
			char padding1[2992];
			resource_size_t physaddr;
		};
		struct {
			char padding2[3320];
			u64 default_desc1;
		};
		struct {
			char padding3[3352];
			dma_addr_t sdma_pad_phys;
		};
		struct {
			char padding4[3376];
			struct sdma_engine *per_sdma;
		};
		struct {
			char padding5[3384];
			struct sdma_vl_map *sdma_map;
		};
		struct {
			char padding6[3432];
			void *piobase;
		};
		struct {
			char padding7[3440];
			void *rcvarray_wc;
		};
		struct {
			char padding8[3648];
			long unsigned int *events;
		};
		struct {
			char padding9[3684];
			u32 chip_rcv_contexts;
		};
		struct {
			char padding10[3688];
			u32 chip_rcv_array_count;
		};
		struct {
			char padding11[6872];
			struct hfi1_pportdata *pport;
		};
		struct {
			char padding12[6896];
			u16 flags;
		};
		struct {
			char padding13[6899];
			u8 first_user_ctxt;
		};
		struct {
			char padding14[6920];
			u64 sc2vl[4];
		};
	};
};
