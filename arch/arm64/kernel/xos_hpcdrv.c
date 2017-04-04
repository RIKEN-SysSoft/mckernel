/* xos_hpcdrv.c COPYRIGHT FUJITSU LIMITED 2017 */

#include <xos_hpcdrv.h>

ACCESS_REG_FUNC(fj_tag_address_ctrl_el1, HPC_FJ_TAG_ADDRESS_CTRL_EL1);
//ACCESS_REG_FUNC(fj_tag_address_ctrl_el2, HPC_FJ_TAG_ADDRESS_CTRL_EL2);

ACCESS_REG_FUNC(pf_ctrl_el1, HPC_PF_CTRL_EL1);
ACCESS_REG_FUNC(pf_stream_detect_ctrl_el0, HPC_PF_STREAM_DETECT_CTRL_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl0_el0, HPC_PF_INJECTION_CTRL0_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl1_el0, HPC_PF_INJECTION_CTRL1_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl2_el0, HPC_PF_INJECTION_CTRL2_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl3_el0, HPC_PF_INJECTION_CTRL3_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl4_el0, HPC_PF_INJECTION_CTRL4_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl5_el0, HPC_PF_INJECTION_CTRL5_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl6_el0, HPC_PF_INJECTION_CTRL6_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl7_el0, HPC_PF_INJECTION_CTRL7_EL0);
ACCESS_REG_FUNC(pf_injection_distance0_el0, HPC_PF_INJECTION_DISTANCE0_EL0);
ACCESS_REG_FUNC(pf_injection_distance1_el0, HPC_PF_INJECTION_DISTANCE1_EL0);
ACCESS_REG_FUNC(pf_injection_distance2_el0, HPC_PF_INJECTION_DISTANCE2_EL0);
ACCESS_REG_FUNC(pf_injection_distance3_el0, HPC_PF_INJECTION_DISTANCE3_EL0);
ACCESS_REG_FUNC(pf_injection_distance4_el0, HPC_PF_INJECTION_DISTANCE4_EL0);
ACCESS_REG_FUNC(pf_injection_distance5_el0, HPC_PF_INJECTION_DISTANCE5_EL0);
ACCESS_REG_FUNC(pf_injection_distance6_el0, HPC_PF_INJECTION_DISTANCE6_EL0);
ACCESS_REG_FUNC(pf_injection_distance7_el0, HPC_PF_INJECTION_DISTANCE7_EL0);

static void hpc_prefetch_regs_init(void)
{
	uint64_t reg = 0;

	/* PF_CTRL_EL1 */
	reg = HPC_PF_CTRL_EL1_EL1AE_ENABLE | HPC_PF_CTRL_EL1_EL0AE_ENABLE;
	xos_access_pf_ctrl_el1(WRITE_ACCESS, &reg);

	/* PF_STREAM_DETECT_CTRL */
	reg = 0;
	xos_access_pf_stream_detect_ctrl_el0(WRITE_ACCESS, &reg);

	/* PF_INJECTION_CTRL */
	reg = 0;
	xos_access_pf_injection_ctrl0_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl1_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl2_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl3_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl4_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl5_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl6_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_ctrl7_el0(WRITE_ACCESS, &reg);

	/* PF_INJECTION_DISTANCE */
	reg = 0;
	xos_access_pf_injection_distance0_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance1_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance2_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance3_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance4_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance5_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance6_el0(WRITE_ACCESS, &reg);
	xos_access_pf_injection_distance7_el0(WRITE_ACCESS, &reg);
}

static void hpc_tag_address_regs_init(void)
{
	uint64_t reg = HPC_FJ_TAG_ADDRESS_CTRL_EL1_TBO0_MASK |
		HPC_FJ_TAG_ADDRESS_CTRL_EL1_SEC0_MASK |
		HPC_FJ_TAG_ADDRESS_CTRL_EL1_PFE0_MASK ;
	/* FJ_TAG_ADDRESS_CTRL */
	xos_access_fj_tag_address_ctrl_el1(WRITE_ACCESS, &reg);
}

void hpc_registers_init(void)
{
	hpc_prefetch_regs_init();
	hpc_tag_address_regs_init();
}
