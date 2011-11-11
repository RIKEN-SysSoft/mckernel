#ifndef HEADER_MCCTRL_H
#define HEADER_MCCTRL_H

#include <aal/aal_host_driver.h>
#include <uprotocol.h>

struct mcctrl_priv { 
	aal_os_t os;
	struct program_load_desc *desc;
};

#endif
