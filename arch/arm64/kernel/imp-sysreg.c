/* imp-sysreg.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sysreg.h>

/* hpc */
ACCESS_REG_FUNC(fj_tag_address_ctrl_el1, IMP_FJ_TAG_ADDRESS_CTRL_EL1);
ACCESS_REG_FUNC(pf_ctrl_el1, IMP_PF_CTRL_EL1);
ACCESS_REG_FUNC(pf_stream_detect_ctrl_el0, IMP_PF_STREAM_DETECT_CTRL_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl0_el0, IMP_PF_INJECTION_CTRL0_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl1_el0, IMP_PF_INJECTION_CTRL1_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl2_el0, IMP_PF_INJECTION_CTRL2_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl3_el0, IMP_PF_INJECTION_CTRL3_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl4_el0, IMP_PF_INJECTION_CTRL4_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl5_el0, IMP_PF_INJECTION_CTRL5_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl6_el0, IMP_PF_INJECTION_CTRL6_EL0);
ACCESS_REG_FUNC(pf_injection_ctrl7_el0, IMP_PF_INJECTION_CTRL7_EL0);
ACCESS_REG_FUNC(pf_injection_distance0_el0, IMP_PF_INJECTION_DISTANCE0_EL0);
ACCESS_REG_FUNC(pf_injection_distance1_el0, IMP_PF_INJECTION_DISTANCE1_EL0);
ACCESS_REG_FUNC(pf_injection_distance2_el0, IMP_PF_INJECTION_DISTANCE2_EL0);
ACCESS_REG_FUNC(pf_injection_distance3_el0, IMP_PF_INJECTION_DISTANCE3_EL0);
ACCESS_REG_FUNC(pf_injection_distance4_el0, IMP_PF_INJECTION_DISTANCE4_EL0);
ACCESS_REG_FUNC(pf_injection_distance5_el0, IMP_PF_INJECTION_DISTANCE5_EL0);
ACCESS_REG_FUNC(pf_injection_distance6_el0, IMP_PF_INJECTION_DISTANCE6_EL0);
ACCESS_REG_FUNC(pf_injection_distance7_el0, IMP_PF_INJECTION_DISTANCE7_EL0);

static void hpc_prefetch_regs_init(void)
{
	uint64_t reg = 0;

	/* PF_CTRL_EL1 */
	reg = IMP_PF_CTRL_EL1_EL1AE_ENABLE | IMP_PF_CTRL_EL1_EL0AE_ENABLE;
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
	uint64_t reg = IMP_FJ_TAG_ADDRESS_CTRL_EL1_TBO0_MASK |
		IMP_FJ_TAG_ADDRESS_CTRL_EL1_SEC0_MASK |
		IMP_FJ_TAG_ADDRESS_CTRL_EL1_PFE0_MASK;

	/* FJ_TAG_ADDRESS_CTRL */
	xos_access_fj_tag_address_ctrl_el1(WRITE_ACCESS, &reg);
}

void hpc_registers_init(void)
{
	hpc_prefetch_regs_init();
	hpc_tag_address_regs_init();
}

/* vhbm */
ACCESS_REG_FUNC(barrier_ctrl_el1, IMP_BARRIER_CTRL_EL1);
ACCESS_REG_FUNC(barrier_bst_bit_el1, IMP_BARRIER_BST_BIT_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb0_el1, IMP_BARRIER_INIT_SYNC_BB0_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb1_el1, IMP_BARRIER_INIT_SYNC_BB1_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb2_el1, IMP_BARRIER_INIT_SYNC_BB2_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb3_el1, IMP_BARRIER_INIT_SYNC_BB3_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb4_el1, IMP_BARRIER_INIT_SYNC_BB4_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb5_el1, IMP_BARRIER_INIT_SYNC_BB5_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w0_el1, IMP_BARRIER_ASSIGN_SYNC_W0_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w1_el1, IMP_BARRIER_ASSIGN_SYNC_W1_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w2_el1, IMP_BARRIER_ASSIGN_SYNC_W2_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w3_el1, IMP_BARRIER_ASSIGN_SYNC_W3_EL1);

void vhbm_barrier_registers_init(void)
{
	uint64_t reg = 0;

	reg = IMP_BARRIER_CTRL_EL1_EL1AE_ENABLE |
		IMP_BARRIER_CTRL_EL1_EL0AE_ENABLE;
	xos_access_barrier_ctrl_el1(WRITE_ACCESS, &reg);

	reg = 0;

	xos_access_barrier_init_sync_bb0_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_init_sync_bb1_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_init_sync_bb2_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_init_sync_bb3_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_init_sync_bb4_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_init_sync_bb5_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_assign_sync_w0_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_assign_sync_w1_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_assign_sync_w2_el1(WRITE_ACCESS, &reg);
	xos_access_barrier_assign_sync_w3_el1(WRITE_ACCESS, &reg);
}

/* sccr */
ACCESS_REG_FUNC(sccr_ctrl_el1, IMP_SCCR_CTRL_EL1);
ACCESS_REG_FUNC(sccr_assign_el1, IMP_SCCR_ASSIGN_EL1);
ACCESS_REG_FUNC(sccr_set0_l2_el1, IMP_SCCR_SET0_L2_EL1);
ACCESS_REG_FUNC(sccr_l1_el0, IMP_SCCR_L1_EL0);

void scdrv_registers_init(void)
{
	uint64_t reg = 0;

	reg = IMP_SCCR_CTRL_EL1_EL1AE_MASK;
	xos_access_sccr_ctrl_el1(WRITE_ACCESS, &reg);

	reg = 0;
	xos_access_sccr_assign_el1(WRITE_ACCESS, &reg);
	xos_access_sccr_l1_el0(WRITE_ACCESS, &reg);

	reg = (14UL << IMP_SCCR_SET0_L2_EL1_L2_SEC0_SHIFT);
	xos_access_sccr_set0_l2_el1(WRITE_ACCESS, &reg);
}
