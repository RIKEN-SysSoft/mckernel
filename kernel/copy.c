#include <aal/dma.h>
#include <amemcpy.h>

int memcpy_async(unsigned long dest, unsigned long src,
                 unsigned long len, int wait, unsigned long *notify)
{
	struct aal_dma_request req;
	unsigned long fin = 0;

	if (notify)
		*notify = 0;
	memset(&req, 0, sizeof(req));
	req.src_phys = src;
	req.dest_phys = dest;
	req.size = len;

	if (notify) {
		req.notify = (void *)virt_to_phys(notify);
		req.priv = (void *)1;
	} else if (wait) {
		req.notify = (void *)virt_to_phys(&fin);
		req.priv = (void *)1;
	}

	aal_mc_dma_request(0, &req);
	if (wait) {
		while (!fin) {
			barrier();
		}
	}

	return 0;
}
