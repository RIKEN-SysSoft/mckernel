if (NOT LIBDWARF)
	add_subdirectory(libdwarf)
endif()

if (ENABLE_UTI)
	if (${ARCH} STREQUAL "arm64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "syscall_intercept/arch/aarch64" CACHE STRINGS "relative path to syscalL_intercept source directory")
	elseif (${ARCH} STREQUAL "x86_64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "syscall_intercept" CACHE STRINGS "relative path to syscalL_intercept source directory")
	endif()

	# syscall_intercept
	# change cmake options only in this directory
	SET(CMAKE_BUILD_TYPE Release CACHE STRING "release build" FORCE)
	SET(TREAT_WARNINGS_AS_ERRORS OFF CACHE BOOL "ignore warnings" FORCE)
	add_subdirectory(${SYSCALL_INTERCEPT_SOURCE_DIR} syscall_intercept)

	# libuti
	find_library(LIBCAP libcap)
	if (NOT LIBCAP)
	  message(FATAL_ERROR "error: couldn't find libcap")
	endif()

	find_library(LIBCAP_DEVEL libcap-devel)
	if (NOT LIBCAP_DEVEL)
	  message(FATAL_ERROR "error: couldn't find libcap-devel")
	endif()

	set(uti_dir ${CMAKE_CURRENT_BINARY_DIR}/uti.dir)
	file(REMOVE_RECURSE ${uti_dir})
	file(MAKE_DIRECTORY ${uti_dir})
	add_custom_target(libuti ALL COMMAND cd ${uti_dir} && ./configure --prefix=${CMAKE_INSTALL_PREFIX} && make install)
endif()
