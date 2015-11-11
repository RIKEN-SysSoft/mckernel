PHDRS 
{
	text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(7);
}
SECTIONS
{
	. = 0xffffffff80001000;
    _head = .;

    .text : {
        *(.text);
    } : text

    . = ALIGN(4096);
	.data : {
	      *(.data)
	      *(.data.*)
	} :data
	.rodata : {
	      *(.rodata .rodata.*)
	} :data

	.vsyscall : ALIGN(0x1000) {
		vsyscall_page = .;

		. = vsyscall_page + 0x000;
		*(.vsyscall.gettimeofday)
		*(.vsyscall.gettimeofday.*)

		. = vsyscall_page + 0x400;
		*(.vsyscall.time)

		. = vsyscall_page + 0x800;
		*(.vsyscall.getcpu)

		. = ALIGN(4096);
	} : data = 0xf4

    .bss : {
          *(.bss .bss.*)
    }
    . = ALIGN(4096);
    _end = .;
}
