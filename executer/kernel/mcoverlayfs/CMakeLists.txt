# LESS/GREATER_EQUAL appears somewhere in 3.7... meh compat until we stop caring about 2.x
# ...apparently can't define macros ot use inside if, so unfold manually

if(NOT (LINUX_VERSION_CODE LESS 262144) AND NOT (LINUX_VERSION_CODE GREATER 262400))
	add_subdirectory("linux-4.0.9")
elseif(NOT (LINUX_VERSION_CODE LESS 263680) AND NOT (LINUX_VERSION_CODE GREATER 263936))
	add_subdirectory("linux-4.6.7")
elseif(LINUX_VERSION_CODE EQUAL 199168)
	add_subdirectory("linux-3.10.0-327.36.1.el7")
else()
	#add_subdirectory("linux-3.10.0-327.36.1.el7")
	add_subdirectory("linux-4.18.14")
	#message(FATAL_ERROR "mcoverlayfs enabled but kernel version not compatible")
endif()
