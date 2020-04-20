configure_file(mckernel.mk.in mckernel.mk @ONLY)

foreach(file IN ITEMS mckernel.c README)
  configure_file(${file} ${CMAKE_CURRENT_BINARY_DIR}/${file} COPYONLY)
endforeach()
