if (NOT LIBDWARF)
	add_subdirectory(libdwarf)
endif()

if (ENABLE_UTI)
	if (${ARCH} STREQUAL "arm64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/syscall_intercept/arch/aarch64" CACHE STRINGS "relative path to syscalL_intercept source directory")
	elseif (${ARCH} STREQUAL "x86_64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/syscall_intercept" CACHE STRINGS "relative path to syscalL_intercept source directory")
	endif()


	# syscall_intercept
	# change cmake options only in this directory
	SET(CMAKE_BUILD_TYPE Release CACHE STRING "release build" FORCE)
	SET(TREAT_WARNINGS_AS_ERRORS OFF CACHE BOOL "ignore warnings" FORCE)
	add_subdirectory(${SYSCALL_INTERCEPT_SOURCE_DIR} syscall_intercept)


	# libuti
	find_path(LIBCAP_INCLUDE_DIRS
	  capability.h
	  PATHS /usr/include/sys
	  NO_DEFAULT_PATH)

	find_library(LIBCAP_LIBRARIES
	  NAME cap
	  PATHS /usr/lib64
	  NO_DEFAULT_PATH)

	if (NOT LIBCAP_INCLUDE_DIRS OR NOT LIBCAP_LIBRARIES)
	  message(FATAL_ERROR "error: couldn't find libcap")
	endif()

 	include(ExternalProject)
	ExternalProject_Add(libuti
 	  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/uti
 	  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/uti
	  CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/uti/configure --disable-static --with-rm=mckernel
 	  BUILD_COMMAND ${MAKE}
	  BUILD_IN_SOURCE FALSE
	  INSTALL_COMMAND ""
	  )

	# Install libuti.so.* into /usr/lib64/mck/ so that mcexec can
	# redirect /usr/lib64/ to /usr/lib64/mck/.  In this way, a.out created
	# by Fujitsu MPICC and thus linked to /usr/lib64/libuti.so
	# can be linked to /usr/lib64/mck/libuti.so when invoked via mcexec.
	ExternalProject_Get_Property(libuti BINARY_DIR)
	foreach(target IN ITEMS libuti.so.1.0.0 libuti.so.1 libuti.so)
	  add_custom_target(${target} ALL COMMAND bash -c "cp -P ${BINARY_DIR}/lib/.libs/${target} ${CMAKE_CURRENT_BINARY_DIR}")
	  add_dependencies(${target} libuti)
	  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${target} DESTINATION "${LIBDIR}/mck")
	endforeach()
endif()
