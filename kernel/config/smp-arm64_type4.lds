/* smp-arm64_type4.lds COPYRIGHT FUJITSU LIMITED 2017-2018 */
PHDRS
{
	text PT_LOAD FLAGS(5);
	data PT_LOAD FLAGS(7);
}
SECTIONS
{
	. = 0xffffffffe0000000; /* KERNEL_START */
	_head = .;

	.text : {
		*(.text);
	} : text

	. = ALIGN(0x10000);
	.data : {
		*(.data)
		*(.data.*)
		. = ALIGN(8);
		__start___verbose = .;
		*(__verbose);
		__stop___verbose = .;
	} :data
	.rodata : {
		*(.rodata .rodata.*)
	} :data

	.vdso : ALIGN(0x10000) {
		vdso_page = .;

		. = vdso_page + 0x00000;
		*(.vdso.data)

		. = vdso_page + 0x10000;
		*(.vdso.text)

		. = ALIGN(0x10000);
	} : data = 0xf4

	.bss : {
		*(.bss .bss.*)
	}
	. = ALIGN(0x10000);
	idmap_page_table = .;
	. += 0x10000;	/* PAGE_SIZE */
	swapper_page_table = .;
	. += 0x10000;	/* PAGE_SIZE */
	idmap_pg_dir = .;
	. += 0x30000;	/* IDMAP_DIR_SIZE */
	swapper_pg_dir = .;
	. += 0x30000;	/* SWAPPER_DIR_SIZE */

	_end = .;
}
