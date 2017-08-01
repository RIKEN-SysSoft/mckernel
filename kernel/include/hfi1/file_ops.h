#ifndef _HFI1_FILE_OPS_H_
#define _HFI1_FILE_OPS_H_

#include <ihk/types.h>
#include <uio.h>

ssize_t hfi1_aio_write(void *private_data, const struct iovec *iovec, unsigned long dim);

#endif