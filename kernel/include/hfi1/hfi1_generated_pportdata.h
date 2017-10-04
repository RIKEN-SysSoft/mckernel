struct hfi1_pportdata {
	union {
		char whole_struct[12544];
		struct {
			char padding0[1907];
			u8 vls_operational;
		};
	};
};
