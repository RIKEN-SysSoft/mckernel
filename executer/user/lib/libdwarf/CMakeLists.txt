if (NOT LIBDWARF)
	# view folders on supported IDEs
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	# used when finding libelf
	set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)

	find_package(LibElf REQUIRED)
	list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBELF_INCLUDE_DIRS})
	include(AutoconfHelper)

	ac_init()
	ac_c_bigendian()
	ac_check_headers(sys/types.h sys/stat.h stdlib.h string.h memory.h strings.h inttypes.h stdint.h unistd.h)
	ac_check_headers(alloca.h elf.h elfaccess.h libelf.h libelf/libelf.h  sys/types.h sys/elf_386.h sys/elf_amd64.h sys/elf_sparc.h sys/ia64/elf.h)

	#  The default libdwarf is the one with struct Elf
	message(STATUS "Assuming struct Elf for the default libdwarf.h")

	# Find out where the elf header is.
	if(HAVE_ELF_H)
		set(HAVE_LOCATION_OF_LIBELFHEADER "<elf.h>")
	elseif(HAVE_LIBELF_H)
		set(HAVE_LOCATION_OF_LIBELFHEADER "<libelf.h>")
	elseif(HAVE_LIBELF_LIBELF_H)
		set(HAVE_LOCATION_OF_LIBELFHEADER "<libelf/libelf.h>")
	endif()

	ac_check_lib(${LIBELF_LIBRARIES} elf64_getehdr)
	ac_check_lib(${LIBELF_LIBRARIES} elf64_getshdr)

	ac_try_compile("
	int main()
	{
		__uint32_t p;
		p = 3;
		return 0;
	}"
	HAVE___UINT32_T)

	ac_try_compile("
	int main()
	{
		__uint64_t p;
		p = 3;
		return 0;
	}"
	HAVE___UINT64_T)

	ac_try_compile("
	#include <sys/types.h>
	int main()
	{
		__uint32_t p;
		p = 3;
		return 0;
	}"
	HAVE___UINT32_T_IN_SYS_TYPES_H)

	ac_try_compile("
	#include <sys/types.h>
	int main()
	{
		__uint64_t p;
		p = 3;
		return 0;
	}"
	HAVE___UINT64_T_IN_SYS_TYPES_H)

	check_c_source_runs("
	static unsigned foo( unsigned x, __attribute__ ((unused)) int y)
	{
		unsigned x2 = x + 1;
		return x2;
	}

	int main(void) {
		unsigned y = 0;
		y = foo(12,y);
		return 0;
	}"
	HAVE_UNUSED_ATTRIBUTE)

	message(STATUS "Checking compiler supports __attribute__ unused... ${HAVE_UNUSED_ATTRIBUTE}")

	ac_try_compile("
	#include <zlib.h>
	int main()
	{
		Bytef dest[100];
		uLongf destlen = 100;
		Bytef *src = 0;
		uLong srclen = 3;
		int res = uncompress(dest,&destlen,src,srclen);
		if (res == Z_OK) {
			 /* ALL IS WELL */
		}
		return 0;
	}"
	HAVE_ZLIB)
	message(STATUS "Checking zlib.h usability... ${HAVE_ZLIB}")
	set(dwfzlib $<$<BOOL:${HAVE_ZIB}>:"z")

	configure_file(libdwarf/libdwarf/libdwarf.h.in libdwarf.h COPYONLY)
	configure_file(libdwarf/libdwarf/config.h.in.cmake config.h)
	set(DWARF_CONFIGURATION_FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h)

	set(DWARF_SOURCES dwarf_abbrev.c dwarf_alloc.c dwarf_arange.c dwarf_die_deliv.c dwarf_dnames.c dwarf_dsc.c dwarf_elf_access.c dwarf_error.c
	dwarf_form.c dwarf_frame.c dwarf_frame2.c dwarf_funcs.c dwarf_gdbindex.c dwarf_global.c dwarf_groups.c dwarf_harmless.c dwarf_init_finish.c dwarf_leb.c
	dwarf_line.c dwarf_loc.c dwarf_macro.c dwarf_macro5.c dwarf_original_elf_init.c dwarf_pubtypes.c dwarf_query.c dwarf_ranges.c dwarf_string.c dwarf_tied.c
	dwarf_str_offsets.c
	dwarf_tsearchhash.c dwarf_types.c dwarf_util.c dwarf_vars.c dwarf_weaks.c dwarf_xu_index.c dwarf_print_lines.c malloc_check.c pro_alloc.c pro_arange.c
	pro_die.c pro_encode_nm.c pro_error.c pro_expr.c pro_finish.c pro_forms.c pro_funcs.c pro_frame.c pro_init.c pro_line.c pro_reloc.c pro_reloc_stream.c
	pro_reloc_symbolic.c pro_pubnames.c pro_section.c pro_types.c pro_vars.c pro_macinfo.c pro_weaks.c)

	set(DWARF_HEADERS dwarf.h dwarf_abbrev.h dwarf_alloc.h dwarf_arange.h dwarf_base_types.h dwarf_die_deliv.h dwarf_dnames.h dwarf_dsc.h
	dwarf_elf_access.h dwarf_error.h dwarf_frame.h dwarf_funcs.h dwarf_gdbindex.h dwarf_global.h dwarf_harmless.h dwarf_incl.h dwarf_line.h dwarf_loc.h
	dwarf_macro.h dwarf_macro5.h dwarf_opaque.h dwarf_reloc_arm.h dwarf_reloc_mips.h dwarf_reloc_ppc.h dwarf_reloc_ppc64.h dwarf_reloc_x86_64.h dwarf_tsearch.h
	dwarf_str_offsets.h
	dwarf_types.h dwarf_util.h dwarf_vars.h dwarf_weaks.h dwarf_xu_index.h dwgetopt.h libdwarfdefs.h malloc_check.h pro_alloc.h pro_arange.h pro_die.h
	pro_encode_nm.h pro_error.h pro_expr.h pro_frame.h pro_incl.h pro_line.h pro_macinfo.h pro_opaque.h pro_reloc.h pro_reloc_stream.h pro_reloc_symbolic.h
	pro_section.h pro_types.h pro_util.h)

	SET(__SRCS "")
		FOREACH(f ${DWARF_SOURCES})
			LIST(APPEND __SRCS "libdwarf/libdwarf/${f}")
		ENDFOREACH(f)
	SET(DWARF_SOURCES ${__SRCS})

	set(GENNAMES_SOURCES
		libdwarf/libdwarf/gennames.c
		libdwarf/libdwarf/dwgetopt.c
		libdwarf/libdwarf/dwarf.h)
	add_executable(gennames ${GENNAMES_SOURCES})
	set(GENNAMES_OUTPUT dwarf_names.c dwarf_names.h dwarf_names_enum.h dwarf_names_new.h)

	add_custom_command(OUTPUT ${GENNAMES_OUTPUT}
		COMMAND gennames -s -i ${CMAKE_CURRENT_SOURCE_DIR}/libdwarf/libdwarf/ -o .
		DEPENDS gennames libdwarf/libdwarf/libdwarf.h.in)

	add_library(dwarf STATIC ${DWARF_SOURCES} ${GENNAMES_OUTPUT} ${DWARF_CONFIGURATION_FILES})
	target_include_directories(dwarf PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libdwarf/libdwarf/")
	target_include_directories(dwarf BEFORE PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
endif()
