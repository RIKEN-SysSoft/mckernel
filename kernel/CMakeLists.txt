set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

configure_file(include/swapfmt.h.in include/swapfmt.h)

execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=include
	OUTPUT_VARIABLE SYSTEM_INCLUDE OUTPUT_STRIP_TRAILING_WHITESPACE)
add_definitions(-D__KERNEL__ -DIHK_OS_MANYCORE)
add_compile_options(-ffreestanding -O2 -nostdinc -isystem ${SYSTEM_INCLUDE} -fno-omit-frame-pointer)
include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}/include"
	"include"
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${PROJECT_BINARY_DIR}"
	"${IHK_FULL_SOURCE_DIR}/cokernel/smp/${ARCH}/include"
	"${IHK_FULL_SOURCE_DIR}/ikc/include"
	"${IHK_FULL_SOURCE_DIR}/linux/include"
	"${PROJECT_SOURCE_DIR}/lib/include"
	"${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/include"
)
if (${ARCH} STREQUAL "x86_64")
	add_compile_options(-mcmodel=large -mno-red-zone -mno-sse)
endif()

set(MCKERNEL_SRCS
	init.c mem.c debug.c mikc.c listeners.c ap.c syscall.c cls.c host.c process.c
	copy.c waitq.c futex.c timer.c plist.c fileobj.c shmobj.c zeroobj.c
	procfs.c devobj.c sysfs.c xpmem.c profile.c freeze.c rbtree.c pager.c

	${IHK_FULL_SOURCE_DIR}/ikc/queue.c ${IHK_FULL_SOURCE_DIR}/ikc/master.c
	${IHK_FULL_SOURCE_DIR}/ikc/manycore.c

	${PROJECT_SOURCE_DIR}/lib/abort.c
	${PROJECT_SOURCE_DIR}/lib/bitmap.c
	${PROJECT_SOURCE_DIR}/lib/bitops.c
	${PROJECT_SOURCE_DIR}/lib/page_alloc.c
	${PROJECT_SOURCE_DIR}/lib/string.c
	${PROJECT_SOURCE_DIR}/lib/vsprintf.c
)

# early boot files: need to disable more options (repeat frmo previous list!)
set(EARLY_BOOT_SRCS
	${IHK_FULL_SOURCE_DIR}/cokernel/smp/x86_64/setup.c
	${PROJECT_SOURCE_DIR}/lib/vsprintf.c
	${PROJECT_SOURCE_DIR}/lib/string.c
	init.c
	debug.c
)


if (BUILD_TARGET STREQUAL "smp-x86")
	list(APPEND MCKERNEL_SRCS
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/cpu.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/interrupt.S
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/memory.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/trampoline.S
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/local.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/context.S
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/perfctr.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/syscall.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/vsyscall.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/gencore.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/mikc.c

		${IHK_FULL_SOURCE_DIR}/cokernel/smp/x86_64/setup.c
		${IHK_FULL_SOURCE_DIR}/cokernel/smp/x86_64/dma.c
		${IHK_FULL_SOURCE_DIR}/cokernel/smp/x86_64/ikc.c
	)

	list(APPEND EARLY_BOOT_SRCS
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/cpu.c
		${PROJECT_SOURCE_DIR}/arch/${ARCH}/kernel/memory.c
	)
	set(EARLY_BOOT_FLAGS
		"-fno-stack-protector")
elseif (BUILD_TARGET STREQUAL "smp-arm64")
	set(EARLY_BOOT_FLAGS
		"-fno-stack-protector")
	add_definitions(-UCONFIG_ARM64_64K_PAGES -DCONFIG_ARM64_VA_BITS=48 -DCONFIG_ARM64_PGTABLE_LEVELS=4 -DCONFIG_NR_CPUS=256 -DNR_CPUS=CONFIG_NR_CPUS -DCONFIG_SMP_MAX_CORES=512 -DCONFIG_HZ=100 -DCONFIG_ARM_GIC_V3=y -DCONFIG_ARM_ARCH_TIMER_EVTSTREAM -DCONFIG_ARM64_SVE)
	foreach(i RANGE 1 100)
		add_definitions(-DPOSTK_DEBUG_ARCH_DEP_${i} -DPOSTK_DEBUG_TEMP_FIX_${i})
	endforeach()
endif()

set_source_files_properties(
	${EARLY_BOOT_SRCS}
	PROPERTIES COMPILE_FLAGS
	${EARLY_BOOT_FLAGS})

add_executable(mckernel.img ${MCKERNEL_SRCS})

set_target_properties(mckernel.img PROPERTIES INSTALL_RPATH "")
set_target_properties(mckernel.img PROPERTIES LINK_FLAGS
	"-e arch_start  -T ${CMAKE_CURRENT_SOURCE_DIR}/config/smp-x86.lds")
#set_target_properties(mckernel.img PROPERTIES LINK_LIBRARIES
#	"-nostdlib -ffreestanding")

install(TARGETS "mckernel.img"
	DESTINATION "${BUILD_TARGET}/kernel")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/swapfmt.h"
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

