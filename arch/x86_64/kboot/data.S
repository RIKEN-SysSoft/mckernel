#ifndef KIMAGE
#error "No kernel image is specified"
#endif

.data
.globl data_start
data_start:
.incbin KIMAGE

