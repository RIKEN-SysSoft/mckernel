cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0005 NEW)
project(uti_libuti C)

execute_process(COMMAND bash -c "gawk '/CPU implementer/ { print \$4; exit; }' /proc/cpuinfo"
  OUTPUT_VARIABLE CPU_IMPLEMENTER OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND bash -c "gawk '/CPU architecture/ { print \$3; exit; }' /proc/cpuinfo"
  OUTPUT_VARIABLE CPU_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND bash -c "gawk '/CPU variant/ { print \$4; exit; }' /proc/cpuinfo"
  OUTPUT_VARIABLE CPU_VARIANT OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND bash -c "gawk '/CPU part/ { print \$4; exit; }' /proc/cpuinfo"
  OUTPUT_VARIABLE CPU_PART OUTPUT_STRIP_TRAILING_WHITESPACE)

if(CPU_IMPLEMENTER STREQUAL "0x46" AND CPU_ARCH STREQUAL "8" AND
    CPU_VARIANT STREQUAL "0x1" AND CPU_PART STREQUAL "0x001")
  message("A64FX detected")
  set(CPU_MODEL "a64fx")
  add_definitions(-D__a64fx__)
endif()

# Options: -DWITH_MCK=<McKernel install directory>
add_definitions(-DWITH_MCK=${WITH_MCK})

execute_process(COMMAND bash -c "grep -E '^OPT_DIR' $ENV{HOME}/.mck_test_config | cut -d= -f2"
  OUTPUT_VARIABLE OPT_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
message("OPT_DIR: ${OPT_DIR}")

execute_process(COMMAND bash -c "grep -E '^BOOTPARAM' $ENV{HOME}/.mck_test_config | cut -d= -f2"
  OUTPUT_VARIABLE BOOTPARAM OUTPUT_STRIP_TRAILING_WHITESPACE)
message("BOOTPARAM: ${BOOTPARAM}")

# for autotest
if(NOT DEFINED CMAKE_INSTALL_PREFIX_SCRIPTS)
       set(CMAKE_INSTALL_PREFIX_SCRIPTS ${CMAKE_INSTALL_PREFIX}/scripts)
endif()

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
add_compile_options(
  -O2
  -g
  ${CFLAGS_WARNING}
  )


# -L, this must be done before adding dependants
link_directories("${WITH_MCK}/lib64/mck")

# -Wl,--rpath=, this must be done before adding dependants
# set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
# set(CMAKE_INSTALL_RPATH "${WITH_MCK}/lib64/mck")

# test driver scripts
foreach(target IN ITEMS
    uti_pthread_create01
    )

  # String replacement
  configure_file(src/${target}.sh.in uti-${target} @ONLY)

  # Install scripts
  install(PROGRAMS ${CMAKE_BINARY_DIR}/uti-${target} DESTINATION ${CMAKE_INSTALL_PREFIX_SCRIPTS})
endforeach()

# programs running on Linux
foreach(target IN ITEMS
    uti_pthread_create01
    )

  # Add C target
  add_executable(${target} src/${target}.c)

  # -I
  target_include_directories(${target}
    PRIVATE ${OPT_DIR}/include
    )

  # -l
  target_link_libraries(${target} PRIVATE pthread uti)

  # Install
  install(TARGETS ${target} DESTINATION bin)

endforeach()
