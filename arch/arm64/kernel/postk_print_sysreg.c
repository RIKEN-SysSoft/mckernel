/* postk_print_sysreg.c COPYRIGHT FUJITSU LIMITED 2016 */
/*
 * usage:
 *    	(gdb) call/x postk_debug_sysreg_ttbr1_el1()
 *      $1 = 0x4e64f000
 */
#define postk_debug_sysreg(sysreg)  __postk_debug_sysreg(sysreg, sysreg)

#define __postk_debug_sysreg(fname, regname)		\
	unsigned long postk_debug_sysreg_ ## fname (void)	\
	{							\
		unsigned long sysreg;				\
		asm volatile(					\
			"mrs    %0, " # regname "\n"		\
			: "=r" (sysreg)				\
			:					\
			: "memory");				\
		return sysreg;					\
	}

/*
 * ARMR Architecture Reference Manual ARMv8, for ARMv8-A architecture profile Errata markup Beta
 *  - Table J-5 Alphabetical index of AArch64 Registers
 */
postk_debug_sysreg(actlr_el1)
postk_debug_sysreg(actlr_el2)
postk_debug_sysreg(actlr_el3)
postk_debug_sysreg(afsr0_el1)
postk_debug_sysreg(afsr0_el2)
postk_debug_sysreg(afsr0_el3)
postk_debug_sysreg(afsr1_el1)
postk_debug_sysreg(afsr1_el2)
postk_debug_sysreg(afsr1_el3)
postk_debug_sysreg(aidr_el1)
postk_debug_sysreg(amair_el1)
postk_debug_sysreg(amair_el2)
postk_debug_sysreg(amair_el3)
/*postk_debug_sysreg(at s12e0r)*/
/*postk_debug_sysreg(at s12e0w)*/
/*postk_debug_sysreg(at s12e1r)*/
/*postk_debug_sysreg(at s12e1w)*/
/*postk_debug_sysreg(at s1e0r)*/
/*postk_debug_sysreg(at s1e0w)*/
/*postk_debug_sysreg(at s1e1r)*/
/*postk_debug_sysreg(at s1e1w)*/
/*postk_debug_sysreg(at s1e2r)*/
/*postk_debug_sysreg(at s1e2w)*/
/*postk_debug_sysreg(at s1e3r)*/
/*postk_debug_sysreg(at s1e3w)*/
postk_debug_sysreg(ccsidr_el1)
postk_debug_sysreg(clidr_el1)
postk_debug_sysreg(cntfrq_el0)
postk_debug_sysreg(cnthctl_el2)
postk_debug_sysreg(cnthp_ctl_el2)
postk_debug_sysreg(cnthp_cval_el2)
postk_debug_sysreg(cnthp_tval_el2)
postk_debug_sysreg(cntkctl_el1)
postk_debug_sysreg(cntp_ctl_el0)
postk_debug_sysreg(cntp_cval_el0)
postk_debug_sysreg(cntp_tval_el0)
postk_debug_sysreg(cntpct_el0)
postk_debug_sysreg(cntps_ctl_el1)
postk_debug_sysreg(cntps_cval_el1)
postk_debug_sysreg(cntps_tval_el1)
postk_debug_sysreg(cntv_ctl_el0)
postk_debug_sysreg(cntv_cval_el0)
postk_debug_sysreg(cntv_tval_el0)
postk_debug_sysreg(cntvct_el0)
postk_debug_sysreg(cntvoff_el2)
postk_debug_sysreg(contextidr_el1)
postk_debug_sysreg(cpacr_el1)
postk_debug_sysreg(cptr_el2)
postk_debug_sysreg(cptr_el3)
postk_debug_sysreg(csselr_el1)
postk_debug_sysreg(ctr_el0)
postk_debug_sysreg(currentel)
postk_debug_sysreg(dacr32_el2)
postk_debug_sysreg(daif)
postk_debug_sysreg(dbgauthstatus_el1)
/*postk_debug_sysreg(dbgbcr<n>_el1)*/
/*postk_debug_sysreg(dbgbvr<n>_el1)*/
postk_debug_sysreg(dbgclaimclr_el1)
postk_debug_sysreg(dbgclaimset_el1)
postk_debug_sysreg(dbgdtr_el0)
postk_debug_sysreg(dbgdtrrx_el0)
postk_debug_sysreg(dbgdtrtx_el0)
postk_debug_sysreg(dbgprcr_el1)
postk_debug_sysreg(dbgvcr32_el2)
/*postk_debug_sysreg(dbgwcr<n>_el1)*/
/*postk_debug_sysreg(dbgwvr<n>_el1)*/
/*postk_debug_sysreg(dc cisw)*/
/*postk_debug_sysreg(dc civac)*/
/*postk_debug_sysreg(dc csw)*/
/*postk_debug_sysreg(dc cvac)*/
/*postk_debug_sysreg(dc cvau)*/
/*postk_debug_sysreg(dc isw)*/
/*postk_debug_sysreg(dc ivac)*/
/*postk_debug_sysreg(dc zva)*/
postk_debug_sysreg(dczid_el0)
postk_debug_sysreg(dlr_el0)
postk_debug_sysreg(dspsr_el0)
postk_debug_sysreg(elr_el1)
postk_debug_sysreg(elr_el2)
postk_debug_sysreg(elr_el3)
postk_debug_sysreg(esr_el1)
postk_debug_sysreg(esr_el2)
postk_debug_sysreg(esr_el3)
postk_debug_sysreg(far_el1)
postk_debug_sysreg(far_el2)
postk_debug_sysreg(far_el3)
postk_debug_sysreg(fpcr)
postk_debug_sysreg(fpexc32_el2)
postk_debug_sysreg(fpsr)
postk_debug_sysreg(hacr_el2)
postk_debug_sysreg(hcr_el2)
postk_debug_sysreg(hpfar_el2)
postk_debug_sysreg(hstr_el2)
/*postk_debug_sysreg(ic iallu)*/
/*postk_debug_sysreg(ic ialluis)*/
/*postk_debug_sysreg(ic ivau)*/
/*postk_debug_sysreg(icc_ap0r0_el1)*/
/*postk_debug_sysreg(icc_ap0r1_el1)*/
/*postk_debug_sysreg(icc_ap0r2_el1)*/
/*postk_debug_sysreg(icc_ap0r3_el1)*/
/*postk_debug_sysreg(icc_ap1r0_el1)*/
/*postk_debug_sysreg(icc_ap1r1_el1)*/
/*postk_debug_sysreg(icc_ap1r2_el1)*/
/*postk_debug_sysreg(icc_ap1r3_el1)*/
/*postk_debug_sysreg(icc_asgi1r_el1)*/
/*postk_debug_sysreg(icc_bpr0_el1)*/
/*postk_debug_sysreg(icc_bpr1_el1)*/
/*postk_debug_sysreg(icc_ctlr_el1)*/
/*postk_debug_sysreg(icc_ctlr_el3)*/
/*postk_debug_sysreg(icc_dir_el1)*/
/*postk_debug_sysreg(icc_eoir0_el1)*/
/*postk_debug_sysreg(icc_eoir1_el1)*/
/*postk_debug_sysreg(icc_hppir0_el1)*/
/*postk_debug_sysreg(icc_hppir1_el1)*/
/*postk_debug_sysreg(icc_iar0_el1)*/
/*postk_debug_sysreg(icc_iar1_el1)*/
/*postk_debug_sysreg(icc_igrpen0_el1)*/
/*postk_debug_sysreg(icc_igrpen1_el1)*/
/*postk_debug_sysreg(icc_igrpen1_el3)*/
/*postk_debug_sysreg(icc_pmr_el1)*/
/*postk_debug_sysreg(icc_rpr_el1)*/
/*postk_debug_sysreg(icc_seien_el1)*/
/*postk_debug_sysreg(icc_sgi0r_el1)*/
/*postk_debug_sysreg(icc_sgi1r_el1)*/
/*postk_debug_sysreg(icc_sre_el1)*/
/*postk_debug_sysreg(icc_sre_el2)*/
/*postk_debug_sysreg(icc_sre_el3)*/
/*postk_debug_sysreg(ich_ap0r0_el2)*/
/*postk_debug_sysreg(ich_ap0r1_el2)*/
/*postk_debug_sysreg(ich_ap0r2_el2)*/
/*postk_debug_sysreg(ich_ap0r3_el2)*/
/*postk_debug_sysreg(ich_ap1r0_el2)*/
/*postk_debug_sysreg(ich_ap1r1_el2)*/
/*postk_debug_sysreg(ich_ap1r2_el2)*/
/*postk_debug_sysreg(ich_ap1r3_el2)*/
/*postk_debug_sysreg(ich_eisr_el2)*/
/*postk_debug_sysreg(ich_elsr_el2)*/
/*postk_debug_sysreg(ich_hcr_el2)*/
/*postk_debug_sysreg(ich_lr<n>_el2)*/
/*postk_debug_sysreg(ich_misr_el2)*/
/*postk_debug_sysreg(ich_vmcr_el2)*/
/*postk_debug_sysreg(ich_vseir_el2)*/
/*postk_debug_sysreg(ich_vtr_el2)*/
postk_debug_sysreg(id_aa64afr0_el1)
postk_debug_sysreg(id_aa64afr1_el1)
postk_debug_sysreg(id_aa64dfr0_el1)
postk_debug_sysreg(id_aa64dfr1_el1)
postk_debug_sysreg(id_aa64isar0_el1)
postk_debug_sysreg(id_aa64isar1_el1)
postk_debug_sysreg(id_aa64mmfr0_el1)
postk_debug_sysreg(id_aa64mmfr1_el1)
postk_debug_sysreg(id_aa64pfr0_el1)
postk_debug_sysreg(id_aa64pfr1_el1)
postk_debug_sysreg(id_afr0_el1)
postk_debug_sysreg(id_dfr0_el1)
postk_debug_sysreg(id_isar0_el1)
postk_debug_sysreg(id_isar1_el1)
postk_debug_sysreg(id_isar2_el1)
postk_debug_sysreg(id_isar3_el1)
postk_debug_sysreg(id_isar4_el1)
postk_debug_sysreg(id_isar5_el1)
postk_debug_sysreg(id_mmfr0_el1)
postk_debug_sysreg(id_mmfr1_el1)
postk_debug_sysreg(id_mmfr2_el1)
postk_debug_sysreg(id_mmfr3_el1)
postk_debug_sysreg(id_pfr0_el1)
postk_debug_sysreg(id_pfr1_el1)
postk_debug_sysreg(ifsr32_el2)
postk_debug_sysreg(isr_el1)
postk_debug_sysreg(mair_el1)
postk_debug_sysreg(mair_el2)
postk_debug_sysreg(mair_el3)
postk_debug_sysreg(mdccint_el1)
postk_debug_sysreg(mdccsr_el0)
postk_debug_sysreg(mdcr_el2)
postk_debug_sysreg(mdcr_el3)
postk_debug_sysreg(mdrar_el1)
postk_debug_sysreg(mdscr_el1)
postk_debug_sysreg(midr_el1)
postk_debug_sysreg(mpidr_el1)
postk_debug_sysreg(mvfr0_el1)
postk_debug_sysreg(mvfr1_el1)
postk_debug_sysreg(mvfr2_el1)
postk_debug_sysreg(nzcv)
postk_debug_sysreg(osdlr_el1)
postk_debug_sysreg(osdtrrx_el1)
postk_debug_sysreg(osdtrtx_el1)
postk_debug_sysreg(oseccr_el1)
postk_debug_sysreg(oslar_el1)
postk_debug_sysreg(oslsr_el1)
postk_debug_sysreg(par_el1)
postk_debug_sysreg(pmccfiltr_el0)
postk_debug_sysreg(pmccntr_el0)
postk_debug_sysreg(pmceid0_el0)
postk_debug_sysreg(pmceid1_el0)
postk_debug_sysreg(pmcntenclr_el0)
postk_debug_sysreg(pmcntenset_el0)
postk_debug_sysreg(pmcr_el0)
/*postk_debug_sysreg(pmevcntr<n>_el0)*/
/*postk_debug_sysreg(pmevtyper<n>_el0)*/
postk_debug_sysreg(pmintenclr_el1)
postk_debug_sysreg(pmintenset_el1)
postk_debug_sysreg(pmovsclr_el0)
postk_debug_sysreg(pmovsset_el0)
postk_debug_sysreg(pmselr_el0)
postk_debug_sysreg(pmswinc_el0)
postk_debug_sysreg(pmuserenr_el0)
postk_debug_sysreg(pmxevcntr_el0)
postk_debug_sysreg(pmxevtyper_el0)
postk_debug_sysreg(revidr_el1)
postk_debug_sysreg(rmr_el1)
postk_debug_sysreg(rmr_el2)
postk_debug_sysreg(rmr_el3)
postk_debug_sysreg(rvbar_el1)
postk_debug_sysreg(rvbar_el2)
postk_debug_sysreg(rvbar_el3)
/*postk_debug_sysreg(s3_<op1>_<cn>_<cm>_<op2>)*/
postk_debug_sysreg(scr_el3)
postk_debug_sysreg(sctlr_el1)
postk_debug_sysreg(sctlr_el2)
postk_debug_sysreg(sctlr_el3)
postk_debug_sysreg(sder32_el3)
postk_debug_sysreg(sp_el0)
postk_debug_sysreg(sp_el1)
postk_debug_sysreg(sp_el2)
/*postk_debug_sysreg(sp_el3)*/
postk_debug_sysreg(spsel)
postk_debug_sysreg(spsr_abt)
postk_debug_sysreg(spsr_el1)
postk_debug_sysreg(spsr_el2)
postk_debug_sysreg(spsr_el3)
postk_debug_sysreg(spsr_fiq)
postk_debug_sysreg(spsr_irq)
postk_debug_sysreg(spsr_und)
postk_debug_sysreg(tcr_el1)
postk_debug_sysreg(tcr_el2)
postk_debug_sysreg(tcr_el3)
postk_debug_sysreg(teecr32_el1)
postk_debug_sysreg(teehbr32_el1)
/*postk_debug_sysreg(tlbi alle1)*/
/*postk_debug_sysreg(tlbi alle1is)*/
/*postk_debug_sysreg(tlbi alle2)*/
/*postk_debug_sysreg(tlbi alle2is)*/
/*postk_debug_sysreg(tlbi alle3)*/
/*postk_debug_sysreg(tlbi alle3is)*/
/*postk_debug_sysreg(tlbi aside1)*/
/*postk_debug_sysreg(tlbi aside1is)*/
/*postk_debug_sysreg(tlbi ipas2e1)*/
/*postk_debug_sysreg(tlbi ipas2e1is)*/
/*postk_debug_sysreg(tlbi ipas2le1)*/
/*postk_debug_sysreg(tlbi ipas2le1is)*/
/*postk_debug_sysreg(tlbi vaae1)*/
/*postk_debug_sysreg(tlbi vaae1is)*/
/*postk_debug_sysreg(tlbi vaale1)*/
/*postk_debug_sysreg(tlbi vaale1is)*/
/*postk_debug_sysreg(tlbi vae1)*/
/*postk_debug_sysreg(tlbi vae1is)*/
/*postk_debug_sysreg(tlbi vae2)*/
/*postk_debug_sysreg(tlbi vae2is)*/
/*postk_debug_sysreg(tlbi vae3)*/
/*postk_debug_sysreg(tlbi vae3is)*/
/*postk_debug_sysreg(tlbi vale1)*/
/*postk_debug_sysreg(tlbi vale1is)*/
/*postk_debug_sysreg(tlbi vale2)*/
/*postk_debug_sysreg(tlbi vale2is)*/
/*postk_debug_sysreg(tlbi vale3)*/
/*postk_debug_sysreg(tlbi vale3is)*/
/*postk_debug_sysreg(tlbi vmalle1)*/
/*postk_debug_sysreg(tlbi vmalle1is)*/
/*postk_debug_sysreg(tlbi vmalls12e1)*/
/*postk_debug_sysreg(tlbi vmalls12e1is)*/
postk_debug_sysreg(tpidr_el0)
postk_debug_sysreg(tpidr_el1)
postk_debug_sysreg(tpidr_el2)
postk_debug_sysreg(tpidr_el3)
postk_debug_sysreg(tpidrro_el0)
postk_debug_sysreg(ttbr0_el1)
postk_debug_sysreg(ttbr0_el2)
postk_debug_sysreg(ttbr0_el3)
postk_debug_sysreg(ttbr1_el1)
postk_debug_sysreg(vbar_el1)
postk_debug_sysreg(vbar_el2)
postk_debug_sysreg(vbar_el3)
postk_debug_sysreg(vmpidr_el2)
postk_debug_sysreg(vpidr_el2)
postk_debug_sysreg(vtcr_el2)
postk_debug_sysreg(vttbr_el2)
