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
	# Install only libuti.so.* into <prefix>/mck/ so that mcexec LD_PRELOAD it.
	# In this way, a.out created by Fujitsu MPI and linked to
	# libuti.so in the standard path can use the McKernel version when
	# invoked through mcexec.
 	ExternalProject_Add(libuti
 	  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/uti
 	  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/uti
	  INSTALL_DIR ${prefix}
	  CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/uti/configure --prefix=<INSTALL_DIR> --libdir=<INSTALL_DIR>/lib64 --disable-static --with-rm=mckernel
 	  BUILD_COMMAND ${MAKE}
	  BUILD_IN_SOURCE FALSE
	  INSTALL_COMMAND ${MAKE} install && bash -c "rm ${prefix}/include/uti.h ${prefix}/lib64/libuti.la && [[ -d ${prefix}/lib64/mck ]] || mkdir ${prefix}/lib64/mck && mv ${prefix}/lib64/libuti.* ${prefix}/lib64/mck"
 	  )
endif()
