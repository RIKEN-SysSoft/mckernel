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
    .bss : {
          *(.bss .bss.*)
    }
    . = ALIGN(4096);
    _end = .;

	/DISCARD/ : {
	     *(.eh_frame)
         *(.note.gnu.build-id)
	}
}
