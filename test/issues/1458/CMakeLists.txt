cmake_policy(SET CMP0005 NEW)

# Options: -DWITH_MCK=<McKernel install directory>
add_definitions(-DWITH_MCK=${WITH_MCK})

# Options: -DWITH_MCK_SRC=<McKernel source directory>
add_definitions(-DWITH_MCK_SRC=${WITH_MCK_SRC})

# not used when integrated with autotest
# Options: -DWITH_MCK_BUILD=<McKernel build directory>
add_definitions(-DWITH_MCK_BUILD=${WITH_MCK_BUILD})

# for autotest
if(NOT DEFINED CMAKE_INSTALL_PREFIX_SCRIPTS)
       set(CMAKE_INSTALL_PREFIX_SCRIPTS ${CMAKE_INSTALL_PREFIX}/scripts)
endif()

cmake_minimum_required(VERSION 2.0)

project(myautotest C)

# CPPFLAGS

# CFLAGS
set(CFLAGS_WARNING "-Wall" "-Wextra" "-Wno-unused-parameter" "-Wno-sign-compare" "-Wno-unused-function" ${EXTRA_WARNINGS} CACHE STRING "Warning flags")
add_compile_options(-O2 -g ${CFLAGS_WARNING})

# -L, this must be done before adding dependants

# -Wl,--rpath=, this must be done before adding dependants
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

foreach(target IN ITEMS
	C1458T01
	C1458T02
	C1458T03
    )

  # Add target
  add_executable(${target} ${target}.c)

  # -D

  # -I

  # -l

  # String replacement and install
  configure_file(${target}.sh.in shmobj-${target} @ONLY)

  # Install
  install(TARGETS ${target} DESTINATION bin)
  install(PROGRAMS ${CMAKE_BINARY_DIR}/shmobj-${target} DESTINATION ${CMAKE_INSTALL_PREFIX_SCRIPTS})
endforeach()

foreach(target IN ITEMS
    common.sh
    )
    configure_file(${target}.in ${target} @ONLY)
    install(PROGRAMS ${CMAKE_BINARY_DIR}/${target} DESTINATION bin)
endforeach()

foreach(target IN ITEMS
	x86_64.conf
    aarch64.conf
    )
    install(FILES ${target} DESTINATION etc)
endforeach()

