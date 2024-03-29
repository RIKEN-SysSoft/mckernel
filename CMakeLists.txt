cmake_minimum_required(VERSION 3.11)

if (NOT CMAKE_BUILD_TYPE)
	set (CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type: Debug Release..." FORCE)
endif (NOT CMAKE_BUILD_TYPE)

enable_language(C ASM)

project(mckernel C ASM)
set(MCKERNEL_VERSION "1.8.0")

# See "Fedora Packaging Guidelines -- Versioning"
set(MCKERNEL_RELEASE "")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
# for rpmbuild
if(DEFINED SYSCONF_INSTALL_DIR)
	set(CMAKE_INSTALL_SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif()

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	set(BUILD_TARGET "smp-x86" CACHE STRING "Build target: smp-x86 | smp-arm64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	set(BUILD_TARGET "smp-arm64" CACHE STRING "Build target: smp-x86 | smp-arm64")
endif()

if (BUILD_TARGET STREQUAL "smp-x86")
	set(ARCH "x86_64")
elseif (BUILD_TARGET STREQUAL "smp-arm64")
	set(ARCH "arm64")
endif()

include(GNUInstallDirs)
include(CMakeParseArguments)
include(Kbuild)
include(CheckCCompilerFlag)
include(AutoconfHelper)

CHECK_C_COMPILER_FLAG(-Wno-implicit-fallthrough IMPLICIT_FALLTHROUGH)
if(IMPLICIT_FALLTHROUGH)
	set(EXTRA_WARNINGS "-Wno-implicit-fallthrough")
endif(IMPLICIT_FALLTHROUGH)

CHECK_C_COMPILER_FLAG(-Wno-stringop-truncation STRINGOP_TRUNCATION)
if(STRINGOP_TRUNCATION)
	list(APPEND EXTRA_WARNINGS "-Wno-stringop-truncation")
endif(STRINGOP_TRUNCATION)

# build options
set(CFLAGS_WARNING "-Wall" "-Wextra" "-Wno-unused-parameter" "-Wno-sign-compare" "-Wno-unused-function" ${EXTRA_WARNINGS} CACHE STRING "Warning flags")
add_compile_options(${CFLAGS_WARNING})

option(ENABLE_WERROR "Enable -Werror" OFF)
if (ENABLE_WERROR)
	add_compile_options("-Werror")
endif(ENABLE_WERROR)

execute_process(COMMAND bash -c "ls -ld /proc/tofu/ 2>/dev/null | wc -l"
  OUTPUT_VARIABLE PROC_TOFU OUTPUT_STRIP_TRAILING_WHITESPACE)

if(PROC_TOFU STREQUAL "1")
	option(ENABLE_TOFU "Built-in tofu driver support" ON)
else()
	option(ENABLE_TOFU "Built-in tofu driver support" OFF)
endif()

if(ENABLE_TOFU)
	add_definitions(-DENABLE_TOFU)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_TOFU")
endif()

# when compiling on a compute-node
execute_process(COMMAND bash -c "grep $(hostname) /etc/opt/FJSVfefs/config/fefs_node1.csv 2>/dev/null | cut -d, -f2 | grep -o CN"
  OUTPUT_VARIABLE FUGAKU_NODE_TYPE OUTPUT_STRIP_TRAILING_WHITESPACE)
if(FUGAKU_NODE_TYPE STREQUAL "CN")
	option(ENABLE_FUGAKU_HACKS "Fugaku hacks" ON)
else()
	option(ENABLE_FUGAKU_HACKS "Fugaku hacks" OFF)
endif()

if(ENABLE_FUGAKU_HACKS)
	add_definitions(-DENABLE_FUGAKU_HACKS)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_FUGAKU_HACKS")
endif()

# Fujitsu MPI tries to xpmem-attach segment with size of range size + 1?
set(FJMPI_VERSION_COMMAND "a=\$(which mpifcc); b=\${a%/*/*}; c=\${b##*/}; d=\${c#*-}; echo \$d")
execute_process(COMMAND bash -c "${FJMPI_VERSION_COMMAND}"
  OUTPUT_VARIABLE FJMPI_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
message("FJMPI_VERSION: ${FJMPI_VERSION}")

if(NOT "${FJMPI_VERSION}" STREQUAL "")
	option(ENABLE_FJMPI_WORKAROUND "Fujitsu MPI workaround" ON)
else()
	option(ENABLE_FJMPI_WORKAROUND "Fujitsu MPI workaround" OFF)
endif()

if(ENABLE_FJMPI_WORKAROUND)
	add_definitions(-DENABLE_FJMPI_WORKAROUND)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_FJMPI_WORKAROUND")
endif()

# krm that mandates reserved memory amount >= available at boot time?
execute_process(COMMAND bash -c "rpm -qi FJSVpxkrm-plugin-mckernel | awk '$1 == \"Version\" && $2 == \":\" { print $3 }'"
  OUTPUT_VARIABLE KRM_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
message("KRM_VERSION: ${KRM_VERSION}")

execute_process(COMMAND bash -c "rpm -qi FJSVpxkrm-plugin-mckernel | awk '$1 == \"Release\" && $2 == \":\" { print $3 }'"
  OUTPUT_VARIABLE KRM_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)
message("KRM_RELEASE: ${KRM_RELEASE}")

if("${KRM_VERSION}" STREQUAL "")
	option(ENABLE_KRM_WORKAROUND "krm workaround" OFF)
elseif("${KRM_VERSION}" VERSION_GREATER_EQUAL 4.0.2 OR
    ("${KRM_VERSION}" VERSION_EQUAL 4.0.1 AND "${KRM_RELEASE}" VERSION_GREATER_EQUAL 25.13.1.0))
	option(ENABLE_KRM_WORKAROUND "krm workaround" OFF)
else()
	option(ENABLE_KRM_WORKAROUND "krm workaround" ON)
endif()

if(ENABLE_KRM_WORKAROUND)
	add_definitions(-DENABLE_KRM_WORKAROUND)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_KRM_WORKAROUND")
endif()

# SIGSTOP instead of SIGSEGV, additional IHK Linux kmsg
option(ENABLE_FUGAKU_DEBUG "Fugaku debug instrumentation" OFF)

if(ENABLE_FUGAKU_DEBUG)
	add_definitions(-DENABLE_FUGAKU_DEBUG)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_FUGAKU_DEBUG")
endif()

# redirect kernel messages to Linux's /dev/kmsg
option(ENABLE_KMSG_REDIRECT "Redirect kernel message to Linux's /dev/kmsg" OFF)

if(ENABLE_KMSG_REDIRECT)
	add_definitions(-DENABLE_KMSG_REDIRECT)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DENABLE_KMSG_REDIRECT")
endif()

option(PROFILE_ENABLE "System call profile" ON)
if(PROFILE_ENABLE)
	add_definitions(-DPROFILE_ENABLE)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DPROFILE_ENABLE")
endif()

option(ENABLE_LINUX_WORK_IRQ_FOR_IKC "Use Linux work IRQ for IKC IPI" ON)
if (ENABLE_LINUX_WORK_IRQ_FOR_IKC)
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} -DIHK_IKC_USE_LINUX_WORK_IRQ")
	add_definitions(-DIHK_IKC_USE_LINUX_WORK_IRQ)
endif()

if (BUILD_TARGET STREQUAL "smp-arm64")
	set(POSTK_DEBUG_DEFINES "-DPOSTK_DEBUG_ARCH_DEP_100 -DPOSTK_DEBUG_ARCH_DEP_42 -DPOSTK_DEBUG_TEMP_FIX_29 -DPOSTK_DEBUG_TEMP_FIX_49")
	add_definitions("${POSTK_DEBUG_DEFINES}")
	set(KBUILD_C_FLAGS "${KBUILD_C_FLAGS} ${POSTK_DEBUG_DEFINES}")

	execute_process(COMMAND awk -F= "$1 == \"CONFIG_ARM64_64K_PAGES\" { print $2; exit; }" "${KERNEL_DIR}/.config"
			OUTPUT_VARIABLE CONFIG_ARM64_64K_PAGES OUTPUT_STRIP_TRAILING_WHITESPACE)
	execute_process(COMMAND awk -F= "$1 == \"CONFIG_ARM64_VA_BITS\" { print $2; exit; }" "${KERNEL_DIR}/.config"
			OUTPUT_VARIABLE CONFIG_ARM64_VA_BITS OUTPUT_STRIP_TRAILING_WHITESPACE)

	message("Host kernel CONFIG_ARM64_64K_PAGES=${CONFIG_ARM64_64K_PAGES}")
	message("Host kernel CONFIG_ARM64_VA_BITS=${CONFIG_ARM64_VA_BITS}")

	if(CONFIG_ARM64_64K_PAGES STREQUAL "y")
		if(CONFIG_ARM64_VA_BITS STREQUAL 42)
			add_definitions(-DCONFIG_ARM64_PGTABLE_LEVELS=2 -DCONFIG_ARM64_VA_BITS=42 -DCONFIG_ARM64_64K_PAGES)
			set(LINKER_SCRIPT "smp-arm64_type3.lds")
		elseif(CONFIG_ARM64_VA_BITS STREQUAL 48)
			add_definitions(-DCONFIG_ARM64_PGTABLE_LEVELS=3 -DCONFIG_ARM64_VA_BITS=48 -DCONFIG_ARM64_64K_PAGES)
			set(LINKER_SCRIPT "smp-arm64_type4.lds")
		endif()
	else(CONFIG_ARM64_64K_PAGES STREQUAL "y")
		if(CONFIG_ARM64_VA_BITS STREQUAL 39)
			add_definitions(-DCONFIG_ARM64_PGTABLE_LEVELS=3 -DCONFIG_ARM64_VA_BITS=39)
			set(LINKER_SCRIPT "smp-arm64_type1.lds")
		elseif(CONFIG_ARM64_VA_BITS STREQUAL 48)
			add_definitions(-DCONFIG_ARM64_PGTABLE_LEVELS=4 -DCONFIG_ARM64_VA_BITS=48)
			set(LINKER_SCRIPT "smp-arm64_type2.lds")
		endif()
	endif(CONFIG_ARM64_64K_PAGES STREQUAL "y")
endif()
set_property(CACHE BUILD_TARGET PROPERTY STRINGS smp-x86 smp-arm64)

# define MAP_KERNEL_START

set(tmpdir ${CMAKE_CURRENT_BINARY_DIR}/tmp.resolve_MODULES_END)
file(REMOVE_RECURSE ${tmpdir})
file(MAKE_DIRECTORY ${tmpdir})
file(WRITE ${tmpdir}/driver.c "#include <linux/module.h>\n")
file(APPEND ${tmpdir}/driver.c "unsigned long MAP_KERNEL_START = MODULES_END - (1UL << 23);\n")
file(WRITE ${tmpdir}/Makefile "obj-m := driver.o\n")
file(APPEND ${tmpdir}/Makefile "all:\n")
file(APPEND ${tmpdir}/Makefile "\tmake ${KBUILD_MAKE_FLAGS_STR} -C ${KERNEL_DIR} M=${tmpdir} modules\n")

execute_process(COMMAND make -C ${tmpdir})
execute_process(COMMAND bash -c "offset=`readelf -S ${tmpdir}/driver.ko | grep .data | sed 's/.* //g'`; echo $((0x$offset))"
  OUTPUT_VARIABLE MAP_KERNEL_START_OFFSET OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND bash -c "dd if=${tmpdir}/driver.ko bs=1 skip=${MAP_KERNEL_START_OFFSET} count=8 2>/dev/null | od -tx8 -Ax | head -1 | sed 's|.* |0x|g'"
  OUTPUT_VARIABLE MAP_KERNEL_START OUTPUT_STRIP_TRAILING_WHITESPACE)


set(ENABLE_MEMDUMP ON)
option(ENABLE_PERF "Enable perf support" ON)
option(ENABLE_RUSAGE "Enable rusage support" ON)
option(ENABLE_QLMPI "Enable qlmpi programs" OFF)
option(ENABLE_UTI "Enable uti support" OFF)
option(ENABLE_UBSAN "Enable undefined behaviour sanitizer on mckernel size" OFF)
option(ENABLE_PER_CPU_ALLOC_CACHE "Enable per-CPU allocator cache (ThunderX2 workaround)" OFF)

find_package(PkgConfig REQUIRED)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)

find_library(LIBRT rt)
if (NOT LIBRT)
	message(FATAL_ERROR "error: couldn't find librt")
endif()
find_library(LIBNUMA numa)
if (NOT LIBNUMA)
	message(FATAL_ERROR "error: couldn't find libnuma")
endif()
find_library(LIBBFD bfd)
if (NOT LIBBFD)
	message(FATAL_ERROR "error: couldn't find libbfd")
endif()
find_library(LIBIBERTY iberty)
if (NOT LIBIBERTY)
	message(FATAL_ERROR "error: couldn't find libiberty")
endif()

find_library(LIBDWARF dwarf)

if (NOT LIBDWARF)
	if (CMAKE_CROSSCOMPILING)
		message(FATAL_ERROR "Could not find libdwarf.so, install libdwarf-devel to ${CMAKE_FIND_ROOT_PATH}")
	endif()
	message("WARNING: libdwarf will be compiled locally")
	enable_language(CXX)
else()
	# Note that libdwarf-devel provides /usr/include/libdwarf/dwarf.h
	# but elfutils-devel provides /usr/include/dwarf.h
	# while mcinspect.c performs "#include <dwarf.h>"
	find_path(DWARF_H dwarf.h PATH_SUFFIXES libdwarf)
endif()

if (ENABLE_QLMPI)
	find_package(MPI REQUIRED)
endif()

string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([0-9]+)(.*))?" "\\1;\\2;\\3;\\5;\\6" LINUX_VERSION ${UNAME_R})
list(GET LINUX_VERSION 0 LINUX_VERSION_MAJOR)
list(GET LINUX_VERSION 1 LINUX_VERSION_MINOR)
list(GET LINUX_VERSION 2 LINUX_VERSION_PATCH)
list(GET LINUX_VERSION 3 LINUX_VERSION_RELEASE)
math(EXPR LINUX_VERSION_CODE "${LINUX_VERSION_MAJOR} * 65536 + ${LINUX_VERSION_MINOR} * 256 + ${LINUX_VERSION_PATCH}")

# compat with various install paths
set(BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
set(SBINDIR ${CMAKE_INSTALL_FULL_SBINDIR})
set(LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR})
set(ETCDIR ${CMAKE_INSTALL_PREFIX}/etc)
set(ROOTFSDIR "/rootfs")
if (CMAKE_INSTALL_PREFIX STREQUAL "/usr")
	set(KMODDIR "/lib/modules/${UNAME_R}/extra/mckernel")
	set(MCKERNELDIR "${CMAKE_INSTALL_FULL_DATADIR}/mckernel/${BUILD_TARGET}")
else()
	set(KMODDIR "${CMAKE_INSTALL_PREFIX}/kmod")
	set(MCKERNELDIR "${CMAKE_INSTALL_PREFIX}/${BUILD_TARGET}/kernel")
endif()
set(prefix ${CMAKE_INSTALL_PREFIX})

# set rpath for everyone
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})

# ihk: ultimately should support extrnal build, but add as subproject for now
if (EXISTS ${PROJECT_SOURCE_DIR}/ihk/CMakeLists.txt)
	set(IHK_SOURCE_DIR "ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
elseif (EXISTS ${PROJECT_SOURCE_DIR}/../ihk/CMakeLists.txt)
	set(IHK_SOURCE_DIR "../ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
else()
	set(IHK_SOURCE_DIR "ihk" CACHE STRINGS "path to ihk source directory from mckernel sources")
endif()
if (EXISTS ${PROJECT_SOURCE_DIR}/${IHK_SOURCE_DIR}/CMakeLists.txt)
	set(IHK_FULL_SOURCE_DIR ${PROJECT_SOURCE_DIR}/${IHK_SOURCE_DIR})
elseif (EXISTS /${IHK_SOURCE_DIR}/CMakeLists.txt)
	set(IHK_FULL_SOURCE_DIR /${IHK_SOURCE_DIR})
else()
	message(FATAL_ERROR "Could not find ihk dir, or it does not contain CMakeLists.txt, either clone ihk or run git submodule update --init")
endif()

add_subdirectory(${IHK_SOURCE_DIR} ihk)

configure_file(config.h.in config.h)

# actual build section - just subdirs
add_subdirectory(executer/kernel/mcctrl)
add_subdirectory(executer/user)
add_subdirectory(kernel)
add_subdirectory(tools/mcstat)
add_subdirectory(tools/crash)

configure_file(scripts/mcreboot-smp.sh.in mcreboot.sh @ONLY)
configure_file(scripts/mcstop+release-smp.sh.in mcstop+release.sh @ONLY)
configure_file(scripts/mcreboot.1in mcreboot.1 @ONLY)
configure_file(scripts/eclair-dump-backtrace.exp.in eclair-dump-backtrace.exp @ONLY)
install(PROGRAMS
		"${CMAKE_CURRENT_BINARY_DIR}/mcreboot.sh"
		"${CMAKE_CURRENT_BINARY_DIR}/mcstop+release.sh"
	DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(PROGRAMS
		"${CMAKE_CURRENT_BINARY_DIR}/eclair-dump-backtrace.exp"
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "scripts/irqbalance_mck.in"
	DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/mcreboot.1"
	DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")


configure_file(scripts/mckernel.spec.in scripts/mckernel.spec @ONLY)
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${MCKERNEL_VERSION}")
set(CPACK_SOURCE_IGNORE_FILES "/.git/;/build;/CMakeCache.txt$;/CMakeFiles$;/Makefile$")
set(CPACK_SOURCE_INSTALLED_DIRECTORIES "${CMAKE_SOURCE_DIR};/;${IHK_FULL_SOURCE_DIR};/ihk;${CMAKE_BINARY_DIR}/scripts;/scripts")
set(CPACK_SOURCE_GENERATOR "TGZ")
include(CPack)
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)


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
message("MAP_KERNEL_START: ${MAP_KERNEL_START}")
message("ENABLE_MEMDUMP: ${ENABLE_MEMDUMP}")
message("ENABLE_PERF: ${ENABLE_PERF}")
message("ENABLE_TOFU: ${ENABLE_TOFU}")
message("ENABLE_FUGAKU_HACKS: ${ENABLE_FUGAKU_HACKS}")
message("ENABLE_FUGAKU_DEBUG: ${ENABLE_FUGAKU_DEBUG}")
message("ENABLE_KRM_WORKAROUND: ${ENABLE_KRM_WORKAROUND}")
message("ENABLE_FJMPI_WORKAROUND: ${ENABLE_FJMPI_WORKAROUND}")
message("PROFILE_ENABLE: ${PROFILE_ENABLE}")
message("ENABLE_RUSAGE: ${ENABLE_RUSAGE}")
message("ENABLE_QLMPI: ${ENABLE_QLMPI}")
message("ENABLE_UTI: ${ENABLE_UTI}")
message("ENABLE_WERROR: ${ENABLE_WERROR}")
message("ENABLE_UBSAN: ${ENABLE_UBSAN}")
message("ENABLE_LINUX_WORK_IRQ_FOR_IKC: ${ENABLE_LINUX_WORK_IRQ_FOR_IKC}")
message("ENABLE_PER_CPU_ALLOC_CACHE: ${ENABLE_PER_CPU_ALLOC_CACHE}")
message("ENABLE_KMSG_REDIRECT: ${ENABLE_KMSG_REDIRECT}")
message("-------------------------------")
