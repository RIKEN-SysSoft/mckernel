#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include "mcctrl.h"

static struct aal_ikc_listen_param __listen_param = {
	.port = 501,
	.handler = test_handler,
	.pkt_size = sizeof(struct ikc_test_packet),
	.queue_size = 4096,
	.magic = 0x29,
};

static long mcexec_prepare_image(struct mcctrl_priv *data, 
                                 struct program_load_desc * __user udesc)
{
	struct program_load_desc desc;

	if (!copy_from_user(&desc, udesc,
	                    sizeof(struct program_load_desc))) {
		return -EFAULT;
	}
	if (desc.num_sections <= 0 || desc.num_sections > 16) {
		return -EINVAL;
	}
	data->desc = kmalloc(sizeof(struct program_load_desc) + 
	                     sizeof(struct program_image_section)
	                     * desc.num_sections, GFP_KERNEL);
	memcpy(data->desc, &desc, sizeof(struct program_load_desc));
	if (!copy_from_user(data->desc->sections, udesc->sections,
	                    sizeof(struct program_image_section)
	                    * desc.num_sections)) {
		kfree(data->desc);
		return -EFAULT;
	}

	return 0;
}

long __mcctrl_control(struct mcctrl_priv *data, unsigned int req,
                      unsigned long arg)
{
	switch (req) {
	case MCEXEC_UP_PREPARE_IMAGE:
		return mcexec_prepare_image((struct mcctrl_priv *)data,
		                            (struct program_load_desc *)arg);
	}
	return -EINVAL;
}

