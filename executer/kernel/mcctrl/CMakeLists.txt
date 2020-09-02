option(ENABLE_GCOV "Enable GCOV" OFF)
if (ENABLE_GCOV)
       add_compile_options("-fprofile-arcs" "-ftest-coverage")
       add_link_options("-lgcov" "--coverage")
endif(ENABLE_GCOV)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/arch/${ARCH})

if(ARCH STREQUAL "x86_64")
	set(ARCH_C_FLAGS "-mno-red-zone -mcmodel=kernel")
endif()

set(MCEXEC_PATH "${CMAKE_INSTALL_FULL_BINDIR}/mcexec" CACHE STRING "mcexec path for binfmt")

kmod(mcctrl
	C_FLAGS
		-I${IHK_FULL_SOURCE_DIR}/linux/include
		-I${IHK_FULL_SOURCE_DIR}/linux/include/ihk/arch/${ARCH}
		-I${IHK_FULL_SOURCE_DIR}/ikc/include
		-I${IHK_FULL_SOURCE_DIR}/ikc/include/ikc/arch/${ARCH}
		-I${IHK_FULL_SOURCE_DIR}/include
		-I${IHK_FULL_SOURCE_DIR}/include/arch/${ARCH}
		-I${PROJECT_SOURCE_DIR}/executer/include
		-I${CMAKE_CURRENT_SOURCE_DIR}/arch/${ARCH}/include
		-I${PROJECT_BINARY_DIR}
		-I${PROJECT_SOURCE_DIR}/kernel/include
		-DMCEXEC_PATH=\\"${MCEXEC_PATH}\\"
		${ARCH_C_FLAGS}
	SOURCES
		driver.c control.c ikc.c syscall.c procfs.c binfmt_mcexec.c
		sysfs.c sysfs_files.c arch/${ARCH}/archdeps.c
	EXTRA_SYMBOLS
		${PROJECT_BINARY_DIR}/ihk/linux/core/Module.symvers
	DEPENDS
		ihk_ko
	INSTALL_DEST
		${KMODDIR}
)
