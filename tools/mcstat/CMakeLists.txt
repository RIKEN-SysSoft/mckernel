include_directories(
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${PROJECT_BINARY_DIR}"
	"${PROJECT_BINARY_DIR}/ihk/linux/include/ihk"
	"${IHK_FULL_SOURCE_DIR}/linux/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/../../executer/include"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)


add_executable(mcstat mcstat.c)
target_link_libraries(mcstat ihklib)

install(TARGETS mcstat
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
