ENTRY(_start)

PHDRS
{
	text PT_LOAD;
	data PT_LOAD;
}

SECTIONS
{
	. = SIZEOF_HEADERS;
    . = ALIGN(4096);
	.text :	{
	      *(.text)
	} :text
	.data : {
	      *(.data)
	      *(.data.*)
	} :data
	.rodata : {
	      *(.rodata .rodata.*)
	} :data

	. = ALIGN(8);
	.bss : {
	     _bss_start = .;
	     *(.bss .bss.*)
	     _bss_end = .;
         . = ALIGN(4096);
         _stack_end = .;
    } :data

	/DISCARD/ : {
	     *(.eh_frame)
         *(.note.gnu.build-id)
	}
}