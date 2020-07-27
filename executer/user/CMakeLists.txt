include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${PROJECT_BINARY_DIR}"
	"${IHK_FULL_SOURCE_DIR}/linux/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/arch/${ARCH}/include"
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}/arch/${ARCH}"
	"${PROJECT_BINARY_DIR}/ihk/linux/include"
)

add_subdirectory(lib)
add_library(libmcexec STATIC arch/${ARCH}/archdep.S)
SET_TARGET_PROPERTIES(libmcexec PROPERTIES OUTPUT_NAME mcexec)
set_property(TARGET libmcexec PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(mcexec mcexec.c)
target_link_libraries(mcexec
	libmcexec ${LIBRT} ${LIBNUMA} $<$<BOOL:ENABLE_QLMPI>:${LIBMPI}> pthread)
target_include_directories(mcexec PUBLIC "${KERNEL_DIR}")
set_property(TARGET mcexec PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET mcexec PROPERTY LINK_FLAGS "-fPIE -pie")

add_executable(mcinspect mcinspect.c)
if (NOT LIBDWARF)
	target_include_directories(mcinspect PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/lib/")
	target_include_directories(mcinspect PRIVATE
		"${CMAKE_CURRENT_SOURCE_DIR}/lib/libdwarf/libdwarf/libdwarf/")
	target_link_libraries(mcinspect dwarf z elf)
else()
	target_include_directories(mcinspect PRIVATE ${DWARF_H})
	target_link_libraries(mcinspect ${LIBDWARF})
endif()
target_link_libraries(mcinspect ${LIBBFD})

add_executable(eclair eclair.c arch/${ARCH}/arch-eclair.c)
target_link_libraries(eclair ${LIBBFD})

add_library(sched_yield SHARED libsched_yield.c)
target_link_libraries(sched_yield dl)
set_property(TARGET sched_yield PROPERTY VERSION 1.0.0)

if (ENABLE_QLMPI)
	target_link_libraries(mcexec ${MPI_C_LIBRARIES})
	target_include_directories(mcexec PRIVATE ${MPI_INCLUDE_PATH})

	add_library(qlmpi qlmpilib.c)
	target_link_libraries(qlmpi ${MPI_C_LIBRARIES})
	target_include_directories(qlmpi PRIVATE ${MPI_INCLUDE_PATH})

	add_library(qlfort libqlfort.c)
	target_link_libraries(qlfort dl ${MPI_C_LIBRARIES})
	target_include_directories(qlfort PRIVATE ${MPI_INCLUDE_PATH})

	add_executable(ql_server ql_server.c)
	add_executable(ql_talker ql_talker.c)

	add_executable(ql_mpiexec_start ql_mpiexec_start.c md5.c)
	target_link_libraries(ql_mpiexec_start pthread)

	add_executable(ql_mpiexec_finalize ql_mpiexec_start.c md5.c)
	set_target_properties(ql_mpiexec_finalize PROPERTIES COMPILE_DEFINITIONS
		QL_MPIEXEC_FINALIZE)
	target_link_libraries(ql_mpiexec_finalize pthread)

	install(TARGETS ql_server ql_talker ql_mpiexec_start ql_mpiexec_finalize
		DESTINATION "${CMAKE_INSTALL_BINDIR}")
	install(TARGETS qlmpi qlfort
		DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

if (ENABLE_UTI)
  #	pkg_check_modules(LIBSYSCALL_INTERCEPT REQUIRED libsyscall_intercept)
  #	link_directories(${CMAKE_CURRENT_BINARY_DIR}/syscall_intercept/lib64)
	if (${ARCH} STREQUAL "arm64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/syscall_intercept/arch/aarch64" CACHE STRINGS "relative path to syscalL_intercept source directory")
	elseif (${ARCH} STREQUAL "x86_64")
	  set(SYSCALL_INTERCEPT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/syscall_intercept" CACHE STRINGS "relative path to syscalL_intercept source directory")
	endif()

	# change cmake options only in this directory
	SET(CMAKE_BUILD_TYPE Release CACHE STRING "release build" FORCE)
	SET(TREAT_WARNINGS_AS_ERRORS OFF CACHE BOOL "ignore warnings" FORCE)
	add_subdirectory(${SYSCALL_INTERCEPT_SOURCE_DIR} syscall_intercept)

	add_library(mck_syscall_intercept SHARED syscall_intercept.c arch/${ARCH}/archdep_c.c)
	if (${ARCH} STREQUAL "arm64")
		set_source_files_properties(syscall_intercept.c PROPERTIES COMPILE_FLAGS -mgeneral-regs-only)
	endif()
	target_link_libraries(mck_syscall_intercept syscall_intercept)
	target_include_directories(mck_syscall_intercept PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/syscall_intercept/include)
	set_target_properties(mck_syscall_intercept PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib64)

	install(TARGETS mck_syscall_intercept
		DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

add_library(ldump2mcdump SHARED ldump2mcdump.c)

configure_file(vmcore2mckdump.in vmcore2mckdump @ONLY)

configure_file(mcexec.1in mcexec.1 @ONLY)
configure_file(mcps.in mcps @ONLY)

install(TARGETS mcexec eclair mcinspect
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(PROGRAMS
	"${CMAKE_CURRENT_BINARY_DIR}/vmcore2mckdump"
	"${CMAKE_CURRENT_BINARY_DIR}/mcps"
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS sched_yield ldump2mcdump
	DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${IHK_FULL_SOURCE_DIR}/linux/include/ihk/ihk_rusage.h"
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ihk")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/mcexec.1"
	DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
