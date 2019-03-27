Linux crash when offlining CPU (el7, hardware-specific)
=========================================================

On some hardware with el7 kernel, linux can crash due to a bug in the
irq handling when offlining CPUs (reserve cpu part of mcreboot)

Example stack trace:
```
[ 4147.052753] BUG: unable to handle kernel NULL pointer dereference at 0000000000000040
[ 4147.060677] IP: [<ffffffff8102ce26>] check_irq_vectors_for_cpu_disable+0x86/0x1c0
[ 4147.068226] PGD 1057e44067 PUD 105f1e7067 PMD 0
[ 4147.072935] Oops: 0000 [#1] SMP
[ 4147.076230] Modules linked in: mcctrl(OE) ihk_smp_x86_64(OE) ihk(OE) xt_CHECKSUM ipt_MASQUERADE nf_nat_masquerade_ipv4 tun rpcsec_gss_krb5 nfsv4 dns_resolver nfs fscache ip6t_rpfilter ipt_REJECT nf_reject_ipv4 ip6t_REJECT nf_reject_ipv6 xt_conntrack ip_set nfnetlink ebtable_nat ebtable_broute bridge stp llc ip6table_nat nf_conntrack_ipv6 nf_defrag_ipv6 nf_nat_ipv6 ip6table_mangle ip6table_security ip6table_raw iptable_nat nf_conntrack_ipv4 nf_defrag_ipv4 nf_nat_ipv4 nf_nat nf_conntrack iptable_mangle iptable_security iptable_raw ebtable_filter ebtables ip6table_filter ip6_tables iptable_filter rpcrdma ib_isert iscsi_target_mod ib_iser libiscsi scsi_transport_iscsi ib_srpt target_core_mod ib_srp scsi_transport_srp scsi_tgt ib_ipoib rdma_ucm ib_ucm ib_uverbs ib_umad rdma_cm ib_cm iw_cm mlx4_ib ib_core
[ 4147.148619]  dm_mirror dm_region_hash dm_log dm_mod sb_edac edac_core intel_powerclamp coretemp ext4 mbcache jbd2 intel_rapl iosf_mbi kvm_intel kvm irqbypass crc32_pclmul ghash_clmulni_intel aesni_intel lrw gf128mul ipmi_ssif glue_helper ablk_helper joydev iTCO_wdt iTCO_vendor_support cryptd ipmi_si ipmi_devintf ipmi_msghandler pcspkr wmi mei_me mei lpc_ich i2c_i801 sg ioatdma shpchp nfsd auth_rpcgss nfs_acl lockd grace sunrpc ip_tables xfs libcrc32c mlx4_en sd_mod crc_t10dif crct10dif_generic mgag200 drm_kms_helper syscopyarea sysfillrect sysimgblt fb_sys_fops ttm isci igb drm mlx4_core libsas ahci libahci scsi_transport_sas libata crct10dif_pclmul ptp crct10dif_common pps_core crc32c_intel dca i2c_algo_bit i2c_core devlink [last unloaded: ihk]
[ 4147.215370] CPU: 6 PID: 38 Comm: migration/6 Tainted: G           OE  ------------ T 3.10.0-693.2.2.el7.x86_64 #1
[ 4147.225672] Hardware name: SGI.COM C1104G-RP5/X9DRG-HF, BIOS 3.0  10/25/2013
[ 4147.232747] task: ffff880174689fa0 ti: ffff8801746ac000 task.ti: ffff8801746ac000
[ 4147.240278] RIP: 0010:[<ffffffff8102ce26>]  [<ffffffff8102ce26>] check_irq_vectors_for_cpu_disable+0x86/0x1c0
[ 4147.250275] RSP: 0018:ffff8801746afd30  EFLAGS: 00010046
[ 4147.255608] RAX: 0000000000000000 RBX: 000000000000004e RCX: 0000000000000000
[ 4147.262770] RDX: 0000000000000020 RSI: 000000000000005f RDI: 0000000000000023
[ 4147.269936] RBP: ffff8801746afd58 R08: 0000000000000001 R09: ffff88017f800490
[ 4147.277103] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000006
[ 4147.284269] R13: 0000000000000000 R14: ffff88085ca82500 R15: 000000000000005f
[ 4147.291429] FS:  0000000000000000(0000) GS:ffff88085fb80000(0000) knlGS:0000000000000000
[ 4147.299556] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 4147.305326] CR2: 0000000000000040 CR3: 0000001059704000 CR4: 00000000001407e0
[ 4147.312490] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[ 4147.319659] DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000400
[ 4147.326827] Stack:
[ 4147.328857]  ffff8808f43078c8 ffff8808f4307850 0000000000000286 ffff8808f4307701
[ 4147.336384]  0000000000000000 ffff8801746afd70 ffffffff81052a82 0000000200000000
[ 4147.343915]  ffff8801746afd88 ffffffff81693ca3 0000000000000003 ffff8801746afdc0
[ 4147.351447] Call Trace:
[ 4147.353921]  [<ffffffff81052a82>] native_cpu_disable+0x12/0x40
[ 4147.359795]  [<ffffffff81693ca3>] take_cpu_down+0x13/0x40
[ 4147.365236]  [<ffffffff81116899>] multi_cpu_stop+0xd9/0x100
[ 4147.370850]  [<ffffffff811167c0>] ? cpu_stop_should_run+0x50/0x50
[ 4147.376983]  [<ffffffff81116ab7>] cpu_stopper_thread+0x97/0x150
[ 4147.382942]  [<ffffffff816a8fad>] ? __schedule+0x39d/0x8b0
[ 4147.388461]  [<ffffffff810b909f>] smpboot_thread_fn+0x12f/0x180
[ 4147.394406]  [<ffffffff810b8f70>] ? lg_double_unlock+0x40/0x40
[ 4147.400276]  [<ffffffff810b098f>] kthread+0xcf/0xe0
[ 4147.405182]  [<ffffffff810b08c0>] ? insert_kthread_work+0x40/0x40
[ 4147.411319]  [<ffffffff816b4f58>] ret_from_fork+0x58/0x90
[ 4147.418893]  [<ffffffff810b08c0>] ? insert_kthread_work+0x40/0x40
[ 4147.426524] Code: 81 fb 00 01 00 00 0f 84 8a 00 00 00 89 d8 65 44 8b 3c 85 20 c6 00 00 45 85 ff 78 e1 44 89 ff e8 91 31 10 00 48 63 15 7e 10 af 00 <48> 8b 70 40 48 c7 c7 80 71 cf 81 49 89 c6 48 83 c2 3f 48 c1 fa
[ 4147.450352] RIP  [<ffffffff8102ce26>] check_irq_vectors_for_cpu_disable+0x86/0x1c0
[ 4147.460135]  RSP <ffff8801746afd30>
[ 4147.465154] CR2: 0000000000000040
```

This bug has been fixed upstream, but redhat will not backport the fixes.
You can work around the problem with a kpatch by backporting the three
following commits:

x86: irq: Get correct available vectors for cpu disable
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ac2a55395eddccd6e3e39532df9869d61e97b2ee

x86/irq: Check for valid irq descriptor in check_irq_vectors_for_cpu_disable()
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d97eb8966c91f2c9d05f0a22eb89ed5b76d966d1

x86/irq: Use proper locking in check_irq_vectors_for_cpu_disable()
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cbb24dc761d95fe39a7a122bb1b298e9604cae15


Alternatively, since it is related to the irq configuration, it might
be possible to mitigate the issue by setting the irq affinities early
on and making sure none of the cpus that will be offlined have any irq
configured.
