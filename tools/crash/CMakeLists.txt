configure_file(mckernel.mk.in mckernel.mk @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mckernel.mk
  DESTINATION ${CMAKE_INSTALL_DATADIR}/tool/crash/)

foreach(file IN ITEMS mckernel.c README)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    DESTINATION ${CMAKE_INSTALL_DATADIR}/tool/crash/)
endforeach()
