# Interface to kbuild
#
# Generate Kbuild file as appropriate and call make to the kernel build system
# Original goal was to be simple, but correctness is difficult...

set(UNAME_R ${CMAKE_SYSTEM_VERSION} CACHE STRING "Kernel version to build against")
set(KERNEL_DIR "/lib/modules/${UNAME_R}/build" CACHE STRING "kernel build directory")

set(KBUILD_C_FLAGS "" CACHE STRING "Compiler flags to give to Kbuild.")
set(KBUILD_MAKE_FLAGS "" CACHE STRING "Extra make arguments for Kbuild.")

mark_as_advanced(
	KBUILD_C_FLAGS
	KBUILD_MAKE_FLAGS
)

if (${CMAKE_GENERATOR} STREQUAL Ninja)
	set(MAKE "make")
	list(APPEND KBUILD_MAKE_FLAGS "-j")
else ()
	set(MAKE "$(MAKE)")
endif ()

# Convert McKernel "arm64" into Linux "aarch64"
if ("${ARCH}" STREQUAL "arm64")
	set(LINUX_ARCH "aarch64")
else ()
	set(LINUX_ARCH "${ARCH}")
endif ()

if (NOT "${LINUX_ARCH}" STREQUAL "${CMAKE_HOST_SYSTEM_PROCESSOR}")
	string(REGEX REPLACE "ld$" "" CROSS_COMPILE "${CMAKE_LINKER}")
	if (CMAKE_CROSSCOMPILING)
	   list(APPEND KBUILD_MAKE_FLAGS "QEMU_LD_PREFIX=${CMAKE_FIND_ROOT_PATH}")
	endif()
	list(APPEND KBUILD_MAKE_FLAGS "ARCH=${ARCH}")
	list(APPEND KBUILD_MAKE_FLAGS "CROSS_COMPILE=${CROSS_COMPILE}")
endif()

string(REPLACE ";" " " KBUILD_MAKE_FLAGS_STR "${KBUILD_MAKE_FLAGS}")

function(kmod MODULE_NAME)
	cmake_parse_arguments(KMOD "" "INSTALL_DEST" "C_FLAGS;SOURCES;EXTRA_SYMBOLS;DEPENDS" ${ARGN})

	add_custom_target(${MODULE_NAME}_ko ALL
		DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}.ko"
			"${CMAKE_CURRENT_BINARY_DIR}/Module.symvers")

	string(REGEX REPLACE "\\.c(;|$)" ".o\\1" KMOD_OBJECTS "${KMOD_SOURCES}")
	string(REPLACE ";" " " OBJECTS "${KMOD_OBJECTS}")
	string(REPLACE ";" " " C_FLAGS "${KMOD_C_FLAGS}")
	string(REPLACE ";" " " EXTRA_SYMBOLS "${KMOD_EXTRA_SYMBOLS}")
if(ENABLE_WERROR)
	set(ccflags "${KBUILD_C_FLAGS} ${C_FLAGS} -Werror")
else(ENABLE_WERROR)
	set(ccflags "${KBUILD_C_FLAGS} ${C_FLAGS}")
endif(ENABLE_WERROR)
	configure_file(${CMAKE_SOURCE_DIR}/cmake/modules/Kbuild.in
		${CMAKE_CURRENT_BINARY_DIR}/Kbuild)

	string(REGEX REPLACE "\\.c(;|$)" ".o.cmd\\1" KMOD_O_CMD "${KMOD_SOURCES}")
	string(REGEX REPLACE "[^/;]+(;|$)" ".\\0" KMOD_O_CMD "${KMOD_O_CMD}")


	# This custom command has two uses:
	# - first is to list kbuild output files, so make clean does something
	#   (cmake does not let us add a custom command to make clean)
	# - this alone could have been added to the other command, but cmake insists
	#   on messing with timestamps with touch_nocreate after the command runs,
	#   so it would incorrectly make intermediary outputs newer than the .ko
	#   and force kbuild to relink needlessly
	add_custom_command(
		OUTPUT
			old_timestamp
			${KMOD_OBJECTS}
			${KMOD_O_CMD}
			"${MODULE_NAME}.o"
			".${MODULE_NAME}.o.cmd"
			"${MODULE_NAME}.mod.c"
			"${MODULE_NAME}.mod.o"
			".${MODULE_NAME}.mod.o.cmd"
			".${MODULE_NAME}.ko.cmd"
			".tmp_versions/${MODULE_NAME}.mod"
			".tmp_versions"
			"modules.order"
		COMMAND touch old_timestamp
	)

	# This custom command forces cmake to rebuild the module, so kbuild's dependencies
	# (including header files modifications) kick in everytime.
	# Ideally, should later be replaced by something parsing the .xxx.cmd files to have
	# the native build system do these checks, if possible at all...
	add_custom_command(OUTPUT kmod_always_rebuild COMMAND touch kmod_always_rebuild)

	if (NOT EXISTS "${KERNEL_DIR}/Makefile")
		message(FATAL_ERROR "${KERNEL_DIR} does not contain a Makefile and is probably missing. install kernel development package or set the KERNEL_DIR variable")
	endif()

	add_custom_command(
		OUTPUT "${MODULE_NAME}.ko"
			"Module.symvers"
		COMMAND ${MAKE} ${KBUILD_MAKE_FLAGS} -C ${KERNEL_DIR}
			M=${CMAKE_CURRENT_BINARY_DIR} modules
		COMMAND rm -f kmod_always_rebuild
		DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/Kbuild"
			${KMOD_DEPENDS}
			kmod_always_rebuild
			old_timestamp
		COMMENT "Building kmod ${MODULE_NAME}"
	)

	if (KMOD_INSTALL_DEST)
		install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}.ko"
			DESTINATION "${KMOD_INSTALL_DEST}")
	endif (KMOD_INSTALL_DEST)

	message("Defined module ${MODULE_NAME}")
endfunction(kmod)
