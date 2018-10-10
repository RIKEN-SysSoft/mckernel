cmake_minimum_required(VERSION 2.6)

if (NOT CMAKE_BUILD_TYPE)
	set (CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type: Debug Release..." FORCE)
endif (NOT CMAKE_BUILD_TYPE)

enable_language(C ASM)

project(mckernel C ASM)
set(MCKERNEL_VERSION "1.6.0")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
include(GNUInstallDirs)
include(CMakeParseArguments)
include(Kbuild)
include(Ksym)
include(CheckCCompilerFlag)

set(CFLAGS_WARNINGS "-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function")
CHECK_C_COMPILER_FLAG(-Wno-implicit-fallthrough IMPLICIT_FALLTHROUGH)
if(IMPLICIT_FALLTHROUGH)
	set(CFLAGS_WARNINGS "${CFLAGS_WARNINGS} -Wno-implicit-fallthrough")
endif(IMPLICIT_FALLTHROUGH)

# C flags need to be set before enabling language?
set(CMAKE_C_FLAGS_DEBUG "-g ${CFLAGS_WARNINGS}" CACHE STRING "Debug compiler flags")
set(CMAKE_C_FLAGS_RELEASE "${CFLAGS_WARNINGS}" CACHE STRING "Release compiler flags")

# build options
option(ENABLE_WERROR "Enable -Werror" OFF)
if (ENABLE_WERROR)
	add_compile_options("-Werror")
endif(ENABLE_WERROR)

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	set(BUILD_TARGET "smp-x86" CACHE STRING "Build target: smp-x86 | smp-arm64")
	set(ARCH "x86_64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	set(BUILD_TARGET "smp-arm64" CACHE STRING "Build target: smp-x86 | smp-arm64")
	set(ARCH "arm64")
	foreach(i RANGE 1 120)
		add_definitions(-DPOSTK_DEBUG_ARCH_DEP_${i} -DPOSTK_DEBUG_TEMP_FIX_${i})
		set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DPOSTK_DEBUG_ARCH_DEP_${i} -DPOSTK_DEBUG_TEMP_FIX_${i}")
	endforeach()
	add_definitions(-DCONFIG_ARM64_64K_PAGES -DCONFIG_ARM64_VA_BITS=48)
endif()
set_property(CACHE BUILD_TARGET PROPERTY STRINGS smp-x86 smp-arm64)

set(ENABLE_MEMDUMP ON)
option(ENABLE_PERF "Enable perf support" ON)
option(ENABLE_RUSAGE "Enable rusage support" ON)
option(ENABLE_MCOVERLAYFS "Enable overlay filesystem" OFF)
option(ENABLE_UBSAN "Enable undefined behaviour sanitizer on mckernel size" OFF)

find_library(LIBRT rt)
find_library(LIBNUMA numa)
find_library(LIBBFD bfd)
find_library(LIBIBERTY iberty)

set(UNAME_R ${CMAKE_SYSTEM_VERSION} CACHE STRING "Kernel version to build against")
string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([0-9]+)(.*))?" "\\1;\\2;\\3;\\5;\\6" LINUX_VERSION ${UNAME_R})
list(GET LINUX_VERSION 0 LINUX_VERSION_MAJOR)
list(GET LINUX_VERSION 1 LINUX_VERSION_MINOR)
list(GET LINUX_VERSION 2 LINUX_VERSION_PATCH)
list(GET LINUX_VERSION 3 LINUX_VERSION_RELEASE)
math(EXPR LINUX_VERSION_CODE "${LINUX_VERSION_MAJOR} * 65536 + ${LINUX_VERSION_MINOR} * 256 + ${LINUX_VERSION_PATCH}")

ksym(sys_mount PREFIX MCCTRL_)
ksym(sys_umount PREFIX MCCTRL_)
ksym(sys_unshare PREFIX MCCTRL_)
ksym(zap_page_range PREFIX MCCTRL_)
ksym(vdso_image_64 PREFIX MCCTRL_)
ksym(vdso_start PREFIX MCCTRL_)
ksym(vdso_end PREFIX MCCTRL_)
ksym(vdso_pages PREFIX MCCTRL_)
ksym(__vvar_page PREFIX MCCTRL_)
ksym(hpet_address PREFIX MCCTRL_)
# POSTK_DEBUG_ARCH_DEP_50, add:find kernel symbol.
ksym(vdso_spec PREFIX MCCTRL_)
ksym(hv_clock PREFIX MCCTRL_)
ksym(sys_readlink PREFIX MCCTRL_)
ksym(walk_page_range PREFIX MCCTRL_)


# compat with various install paths
set(MCKERNEL_LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR})
set(BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
set(SBINDIR ${CMAKE_INSTALL_FULL_SBINDIR})
set(ETCDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR})
set(ROOTFSDIR "${CMAKE_INSTALL_PREFIX}/rootfs")
set(KMODDIR "${CMAKE_INSTALL_PREFIX}/kmod")
set(prefix ${CMAKE_INSTALL_PREFIX})

# set rpath for everyone
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})

# ihk: ultimately should support extrnal build, but add as subproject for now
if (EXISTS ${PROJECT_SOURCE_DIR}/ihk)
	set(IHK_SOURCE_DIR "ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
elseif (EXISTS ${PROJECT_SOURCE_DIR}/../ihk)
	set(IHK_SOURCE_DIR "../ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
else()
	set(IHK_SOURCE_DIR "ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
endif()
if (EXISTS ${PROJECT_SOURCE_DIR}/${IHK_SOURCE_DIR})
	set(IHK_FULL_SOURCE_DIR ${PROJECT_SOURCE_DIR}/${IHK_SOURCE_DIR})
elseif (EXISTS /${IHK_SOURCE_DIR})
	set(IHK_FULL_SOURCE_DIR /${IHK_SOURCE_DIR})
else()
	message(FATAL_ERROR "Could not find ihk dir, either clone ihk or run git submodule update --init")
endif()

add_subdirectory(${IHK_SOURCE_DIR} ihk)

configure_file(config.h.in config.h)

# actual build section - just subdirs
add_subdirectory(executer/kernel/mcctrl)
if (ENABLE_MCOVERLAYFS)
	add_subdirectory(executer/kernel/mcoverlayfs)
endif()
add_subdirectory(executer/user)
add_subdirectory(kernel)
add_subdirectory(tools/mcstat)

configure_file(arch/x86_64/tools/mcreboot-smp-x86.sh.in mcreboot.sh @ONLY)
configure_file(arch/x86_64/tools/mcstop+release-smp-x86.sh.in mcstop+release.sh @ONLY)
configure_file(arch/x86_64/tools/mcoverlay-create-smp-x86.sh.in mcoverlay-create.sh @ONLY)
configure_file(arch/x86_64/tools/mcoverlay-destroy-smp-x86.sh.in mcoverlay-destroy.sh @ONLY)
configure_file(arch/x86_64/tools/mcreboot.1in mcreboot.1 @ONLY)
install(PROGRAMS
		"${CMAKE_CURRENT_BINARY_DIR}/mcreboot.sh"
		"${CMAKE_CURRENT_BINARY_DIR}/mcstop+release.sh"
		"${CMAKE_CURRENT_BINARY_DIR}/mcoverlay-create.sh"
		"${CMAKE_CURRENT_BINARY_DIR}/mcoverlay-destroy.sh"
	DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(FILES
		"arch/x86_64/tools/irqbalance_mck.service"
		"arch/x86_64/tools/irqbalance_mck.in"
	DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/mcreboot.1"
	DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")


# config report
message("-------------------------------")
message("Option summary")
message("-------------------------------")
message("Build type: ${CMAKE_BUILD_TYPE}")
message("Build target: ${BUILD_TARGET}")
message("IHK_SOURCE_DIR: ${IHK_SOURCE_DIR} (relative to mckernel source tree)")
message("UNAME_R: ${UNAME_R}")
message("KERNEL_DIR: ${KERNEL_DIR}")
message("SYSTEM_MAP: ${SYSTEM_MAP}")
message("VMLINUX: ${VMLINUX}")
message("KBUILD_C_FLAGS: ${KBUILD_C_FLAGS}")
message("ENABLE_MEMDUMP: ${ENABLE_MEMDUMP}")
message("ENABLE_PERF: ${ENABLE_PERF}")
message("ENABLE_RUSAGE: ${ENABLE_RUSAGE}")
message("ENABLE_MCOVERLAYFS: ${ENABLE_MCOVERLAYFS}")
message("ENABLE_WERROR: ${ENABLE_WERROR}")
message("ENABLE_UBSAN: ${ENABLE_UBSAN}")
message("-------------------------------")
