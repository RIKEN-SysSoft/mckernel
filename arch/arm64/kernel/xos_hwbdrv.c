/* xos_hwbdrv.c COPYRIGHT FUJITSU LIMITED 2017 */
#include <xos_hwbdrv.h>

/***** FUNCTIONS *****/
ACCESS_REG_FUNC(barrier_ctrl_el1, VHBM_BARRIER_CTRL_EL1);
ACCESS_REG_FUNC(barrier_bst_bit_el1, VHBM_BARRIER_BST_BIT_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb0_el1, VHBM_BARRIER_INIT_SYNC_BB0_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb1_el1, VHBM_BARRIER_INIT_SYNC_BB1_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb2_el1, VHBM_BARRIER_INIT_SYNC_BB2_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb3_el1, VHBM_BARRIER_INIT_SYNC_BB3_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb4_el1, VHBM_BARRIER_INIT_SYNC_BB4_EL1);
ACCESS_REG_FUNC(barrier_init_sync_bb5_el1, VHBM_BARRIER_INIT_SYNC_BB5_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w0_el1, VHBM_BARRIER_ASSIGN_SYNC_W0_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w1_el1, VHBM_BARRIER_ASSIGN_SYNC_W1_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w2_el1, VHBM_BARRIER_ASSIGN_SYNC_W2_EL1);
ACCESS_REG_FUNC(barrier_assign_sync_w3_el1, VHBM_BARRIER_ASSIGN_SYNC_W3_EL1);

void vhbm_barrier_registers_init(void)
{
	uint64_t reg = 0;

	reg = VHBM_BARRIER_CTRL_EL1_EL1AE_ENABLE | VHBM_BARRIER_CTRL_EL1_EL0AE_ENABLE;
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
