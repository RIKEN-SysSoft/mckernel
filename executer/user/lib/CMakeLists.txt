if (NOT LIBDWARF)
	add_subdirectory(libdwarf)
endif()

if (ENABLE_UTI)
	if (${ARCH} STREQUAL "arm64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/syscall_intercept/arch/aarch64" CACHE STRINGS "relative path to syscalL_intercept source directory")
	elseif (${ARCH} STREQUAL "x86_64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/syscall_intercept" CACHE STRINGS "relative path to syscalL_intercept source directory")
	endif()

	# change cmake options only in this directory
	SET(CMAKE_BUILD_TYPE Release CACHE STRING "release build" FORCE)
	SET(TREAT_WARNINGS_AS_ERRORS OFF CACHE BOOL "ignore warnings" FORCE)
	add_subdirectory(${SYSCALL_INTERCEPT_SOURCE_DIR} syscall_intercept)
endif()
