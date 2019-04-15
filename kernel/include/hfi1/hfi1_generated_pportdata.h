struct hfi1_pportdata {
	union {
		char whole_struct[12992];
		struct {
			char padding0[2113];
			u8 vls_operational;
		};
	};
};
