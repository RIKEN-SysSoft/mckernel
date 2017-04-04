/* xos_secdrv.c COPYRIGHT FUJITSU LIMITED 2017 */
#include <xos_secdrv.h>

ACCESS_REG_FUNC(sccr_ctrl_el1, XOS_SCCR_CTRL_EL1);
ACCESS_REG_FUNC(sccr_assign_el1, XOS_SCCR_ASSIGN_EL1);
ACCESS_REG_FUNC(sccr_set0_l2_el1, XOS_SCCR_SET0_L2_EL1);
ACCESS_REG_FUNC(sccr_set1_l2_el1, XOS_SCCR_SET1_L2_EL1);
ACCESS_REG_FUNC(sccr_l1_el0, XOS_SCCR_L1_EL0);
//ACCESS_REG_FUNC(sccr_vsccr_l2_el0, XOS_SCCR_VSCCR_L2_EL0);
ACCESS_REG_FUNC(csselr_el1, XOS_CSSELR_EL1);
ACCESS_REG_FUNC(ccsidr_el1, XOS_CCSIDR_EL1);

void scdrv_registers_init(void)
{
	uint64_t reg = 0;

	reg = XOS_SCCR_CTRL_EL1_EL1AE_MASK;
	xos_access_sccr_ctrl_el1(WRITE_ACCESS, &reg);

	reg = 0;
	xos_access_sccr_assign_el1(WRITE_ACCESS, &reg);
	xos_access_sccr_l1_el0(WRITE_ACCESS, &reg);

	reg = (14UL << XOS_SCCR_SET0_L2_EL1_L2_SEC0_SHIFT);
	xos_access_sccr_set0_l2_el1(WRITE_ACCESS, &reg);
}
