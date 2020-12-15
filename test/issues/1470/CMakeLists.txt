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

# find first NUMA available to user (0 or 4 now)
execute_process(COMMAND bash -c "awk -v keyword=nr_free_pages -f ${CMAKE_CURRENT_SOURCE_DIR}/src/zoneinfo.awk /proc/zoneinfo | awk -v page_size=$(getconf PAGE_SIZE) -f ${CMAKE_CURRENT_SOURCE_DIR}/src/zoneinfo_filter.awk | head -n1" OUTPUT_VARIABLE FIRST_USER_NUMA OUTPUT_STRIP_TRAILING_WHITESPACE)
message("FIRST_USER_NUMA: ${FIRST_USER_NUMA}")
add_definitions(-DFIRST_USER_NUMA=${FIRST_USER_NUMA})

if (FIRST_USER_NUMA STREQUAL "4")
  execute_process(COMMAND sudo bash -c "echo 0-7 > /sys/fs/cgroup/cpuset/system.slice/cpuset.mems")
endif()

cmake_policy(SET CMP0005 NEW)

# Options: -DWITH_MCK=<McKernel install directory>
add_definitions(-DWITH_MCK=${WITH_MCK})

# Options: -DWITH_MCK_SRC=<McKernel source directory>
add_definitions(-DWITH_MCK_SRC=${WITH_MCK_SRC})

# for autotest
if(NOT DEFINED CMAKE_INSTALL_PREFIX_SCRIPTS)
       set(CMAKE_INSTALL_PREFIX_SCRIPTS ${CMAKE_INSTALL_PREFIX}/scripts)
endif()

cmake_minimum_required(VERSION 3.0)

project(issue1470 C)

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

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_definitions(-DBUILD_TARGET=smp-x86)
  add_definitions(-DKMOD_POSTFIX=smp_x86)
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  add_definitions(-DBUILD_TARGET=smp-arm64)
  add_definitions(-DKMOD_POSTFIX=smp_arm64)
endif()

add_definitions(-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX})

# CFLAGS
set(CFLAGS_WARNING "-Wall" "-Wextra" "-Wno-unused-parameter" "-Wno-sign-compare" "-Wno-unused-function" ${EXTRA_WARNINGS} CACHE STRING "Warning flags")
add_compile_options(
  -O2
  -g
  ${CFLAGS_WARNING}
  )


# -L, this must be done before adding dependants
link_directories("${WITH_MCK}/lib64")

# -Wl,--rpath=, this must be done before adding dependants
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_INSTALL_RPATH "${WITH_MCK}/lib64")

# test driver scripts
foreach(target IN ITEMS
    OMPI_MCA_plm_ple_memory_allocation_policy01
    OMPI_MCA_plm_ple_memory_allocation_policy02
    OMPI_MCA_plm_ple_memory_allocation_policy03
    OMPI_MCA_plm_ple_memory_allocation_policy04
    OMPI_MCA_plm_ple_memory_allocation_policy05
    OMPI_MCA_plm_ple_memory_allocation_policy06
    OMPI_MCA_plm_ple_memory_allocation_policy07
    )

  # String replacement
  configure_file(src/${target}.sh.in ihklib-${target} @ONLY)

  # Install scripts
  install(PROGRAMS ${CMAKE_BINARY_DIR}/ihklib-${target} DESTINATION ${CMAKE_INSTALL_PREFIX_SCRIPTS})
endforeach()

# programs running on McKernel
foreach(target IN ITEMS
    check_mempolicy
    )

  # Add C target
  add_executable(${target} src/${target}.c)

  # -I
  target_include_directories(${target}
    PRIVATE "${PROJECT_SOURCE_DIR}/include"
    )

  # -l
  target_link_libraries(${target} PRIVATE numa)

  # Install
  install(TARGETS ${target} DESTINATION bin)

endforeach()
