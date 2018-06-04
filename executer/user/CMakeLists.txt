include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${PROJECT_BINARY_DIR}"
	"${IHK_FULL_SOURCE_DIR}/linux/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/arch/${ARCH}/include"
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}/arch/${ARCH}"
	"${PROJECT_BINARY_DIR}/ihk/linux/include"
)


add_library(libmcexec STATIC arch/${ARCH}/archdep.S)
SET_TARGET_PROPERTIES(libmcexec PROPERTIES OUTPUT_NAME mcexec)
set_property(TARGET libmcexec PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(mcexec mcexec.c)
target_link_libraries(mcexec
	libmcexec ihklib ${LIBRT} ${LIBNUMA} $<$<BOOL:ENABLE_QLMPI>:${LIBMPI}> pthread)
target_include_directories(mcexec PUBLIC "${KERNEL_DIR}")
set_property(TARGET mcexec PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET mcexec PROPERTY LINK_FLAGS "-fPIE -pie")

add_executable(eclair eclair.c arch/${ARCH}/arch-eclair.c)
target_link_libraries(eclair ${LIBBFD})

add_library(sched_yield SHARED libsched_yield.c)
target_link_libraries(sched_yield dl)
set_property(TARGET sched_yield PROPERTY VERSION 1.0.0)

if (ENABLE_QLMPI)
	add_library(qlmpi qlmpilib.c)
	add_library(qlfort libqlfort.c)
	target_link_libraries(qlfort dl)
	add_executable(ql_server ql_server.c)
	add_executable(ql_mpiexec_start ql_mpiexec_start.c md5.c)
	add_executable(ql_talker ql_talker.c)
	target_link_libraries(ql_mpiexec_start pthread)
	set_source_file_properties(ql_mpiexec_finalize.c PROPERTIES COMPILE_DEFINITIONS
		-DQL_MPIEXEC_FINALIZE)
	add_executable(ql_mpiexec_finalize ql_mpiexec_finalize.c md5.c)
	install(TARGETS ql_server ql_talker ql_mpiexec_start ql_mpiexec_finalize
		DESTINATION "${CMAKE_INSTALL_BINDIR}")
	install(TARGETS qlmpi qlfort
		DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

if (ENABLE_UTI)
	add_library(mck_syscall_intercept SHARED arch/${ARCH}/archdep_c.c)
	target_link_libraries(mck_syscall_intercept ${LIBSYSCALL_INTERCEPT})
	set_target_properties(mck_syscall_intercept PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
	install(TARGETS mck_syscall_intercept
		DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

add_executable(ql_talker ql_talker.c)

add_library(ldump2mcdump SHARED ldump2mcdump.c)

configure_file(vmcore2mckdump.in vmcore2mckdump @ONLY)

configure_file(mcexec.1in mcexec.1 @ONLY)

install(TARGETS mcexec eclair
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/vmcore2mckdump"
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS sched_yield ldump2mcdump
	DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "../include/ihklib_rusage.h"
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/mckernel")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/mcexec.1"
	DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
