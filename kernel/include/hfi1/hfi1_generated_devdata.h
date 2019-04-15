struct hfi1_devdata {
	union {
		char whole_struct[7808];
		struct {
			char padding0[3368];
			u8 *kregbase1;
		};
		struct {
			char padding1[3376];
			resource_size_t physaddr;
		};
		struct {
			char padding2[3704];
			u64 default_desc1;
		};
		struct {
			char padding3[3736];
			dma_addr_t sdma_pad_phys;
		};
		struct {
			char padding4[3760];
			struct sdma_engine *per_sdma;
		};
		struct {
			char padding5[3768];
			struct sdma_vl_map *sdma_map;
		};
		struct {
			char padding6[3816];
			void *piobase;
		};
		struct {
			char padding7[3824];
			void *rcvarray_wc;
		};
		struct {
			char padding8[4040];
			long unsigned int *events;
		};
		struct {
			char padding9[4076];
			u32 chip_rcv_contexts;
		};
		struct {
			char padding10[4080];
			u32 chip_rcv_array_count;
		};
		struct {
			char padding11[7264];
			struct hfi1_pportdata *pport;
		};
		struct {
			char padding12[7296];
			u16 flags;
		};
		struct {
			char padding13[7299];
			u8 first_dyn_alloc_ctxt;
		};
		struct {
			char padding14[7368];
			u64 sc2vl[4];
		};
	};
};
