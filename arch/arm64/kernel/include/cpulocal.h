/* cpulocal.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_CPULOCAL_H
#define __HEADER_ARM64_COMMON_CPULOCAL_H

#include <types.h>
#include <registers.h>
#include <thread_info.h>

union arm64_cpu_local_variables *get_arm64_cpu_local_variable(int id);
union arm64_cpu_local_variables *get_arm64_this_cpu_local(void);
void *get_arm64_this_cpu_kstack(void);

#endif /* !__HEADER_ARM64_COMMON_CPULOCAL_H */
