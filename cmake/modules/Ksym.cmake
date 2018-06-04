# Lookup symbol addresses from Ksymbol file

set(SYSTEM_MAP "${KERNEL_DIR}/System.map" CACHE STRING "System map to look for symbols")
set(VMLINUX "${KERNEL_DIR}/vmlinux" CACHE STRING "kernel object file")


function(ksym SYMBOL)
	cmake_parse_arguments(KSYM "" "PREFIX;SOURCE_FILE;SUFFIX" "" ${ARGN})

	execute_process(COMMAND awk "/ ${SYMBOL}$/ { print $1 }" ${SYSTEM_MAP}
		OUTPUT_VARIABLE ADDRESS_CANDIDATES OUTPUT_STRIP_TRAILING_WHITESPACE)

	if (NOT ADDRESS_CANDIDATES)
		return()
	endif()

	# listify and get first element
	string(REPLACE "\n" ";" ADDRESS_CANDIDATES "${ADDRESS_CANDIDATES}")
	list(GET ADDRESS_CANDIDATES 0 ADDRESS)

	if (SOURCE_FILE)
		foreach(ADDRESS IN LISTS ADDRESS_CANDIDATES)
			execute_process(COMMAND addr2line -e ${VMLINUX} ${ADDRESS}
				OUTPUT_VARIABLE LINE OUTPUT_STRIP_TRAILING_WHITESPACE)
			if(LINE MATCHES ".*${SOURCE_FILE}:.*")
				set(FOUND ADDRESS)
				break()
			endif()
		endforeach(ADDRESS)
		if(NOT FOUND)
			return()
		endif()

		# ?! why only if source_file?...
		execute_process(COMMAND "awk '/ __ksymtab_${SYMBOL}$/ { print $1 }'"
			OUTPUT_VARIABLE SYMBOL_EXPORTED OUTPUT_STRIP_TRAILING_WHITESPACE)
		if (SYMBOL_EXPORTED)
			set(ADDRESS 0)
		endif(SYMBOL_EXPORTED)
	endif(SOURCE_FILE)

	set(${KSYM_PREFIX}KSYM_${SYMBOL}${KSYM_SUFFIX} "0x${ADDRESS}" CACHE INTERNAL "symbol")
endfunction(ksym)
