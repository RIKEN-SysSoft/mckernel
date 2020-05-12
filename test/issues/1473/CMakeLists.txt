cmake_policy(SET CMP0005 NEW)

# Options: -DWITH_XPMEM=<XPMEM install directory>
add_definitions(-DWITH_XPMEM=${WITH_XPMEM})

# Options: -DWITH_MCK=<McKernel install directory>
add_definitions(-DWITH_MCK=${WITH_MCK})

# Options: -DWITH_MCK_SRC=<McKernel source directory>
add_definitions(-DWITH_MCK_SRC=${WITH_MCK_SRC})

# for autotest
if(NOT DEFINED CMAKE_INSTALL_PREFIX_SCRIPTS)
       set(CMAKE_INSTALL_PREFIX_SCRIPTS ${CMAKE_INSTALL_PREFIX}/scripts)
endif()

cmake_minimum_required(VERSION 2.0)

project(xpmemtest C)

# CPPFLAGS

set(UNAME_R ${CMAKE_SYSTEM_VERSION} CACHE STRING "Kernel version to build against")
set(KERNEL_DIR "/lib/modules/${UNAME_R}/build" CACHE STRING "kernel build directory")
execute_process(COMMAND awk -F= "$1 == \"CONFIG_ARM64_64K_PAGES\" { print $2; exit; }" "${KERNEL_DIR}/.config"
	OUTPUT_VARIABLE CONFIG_ARM64_64K_PAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	if(CONFIG_ARM64_64K_PAGES STREQUAL "y")
		set(PAGE_SIZE "65536")
	else()
		set(PAGE_SIZE "4096")
	endif()
else()
		set(PAGE_SIZE "4096")
endif()
message("PAGE_SIZE: ${PAGE_SIZE}")

# CFLAGS
set(CFLAGS_WARNING "-Wall" "-Wextra" "-Wno-unused-parameter" "-Wno-sign-compare" "-Wno-unused-function" ${EXTRA_WARNINGS} CACHE STRING "Warning flags")
add_compile_options(-O2 -g ${CFLAGS_WARNING})

# -L, this must be done before adding dependants
link_directories("${WITH_XPMEM}/lib")

# -Wl,--rpath=, this must be done before adding dependants
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

foreach(target IN ITEMS
    xpmem_make01
    xpmem_attach01
    xpmem_attach02
    )

  # Add target
  add_executable(${target} ${target}.c)

  # -D
  target_compile_definitions(${target}
    PRIVATE -DPAGE_SIZE=${PAGE_SIZE}
    )

  # -I
  target_include_directories(${target}
    PRIVATE "${WITH_XPMEM}/include"
    )

  # -l
  target_link_libraries(${target}
    PRIVATE xpmem
    )

  # String replacement and install
  configure_file(${target}.sh.in xpmem-${target} @ONLY)

  # Install
  install(TARGETS ${target} DESTINATION bin)
  install(PROGRAMS ${CMAKE_BINARY_DIR}/xpmem-${target} DESTINATION ${CMAKE_INSTALL_PREFIX_SCRIPTS})
endforeach()

foreach(target IN ITEMS
    common.sh
    )
    configure_file(${target}.in ${target} @ONLY)
    install(PROGRAMS ${CMAKE_BINARY_DIR}/${target} DESTINATION bin)
endforeach()

foreach(target IN ITEMS
    aarch64.conf
    )
    install(FILES ${target} DESTINATION etc)
endforeach()
