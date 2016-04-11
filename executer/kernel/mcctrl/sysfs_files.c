/**
 * \file sysfs_files.c
 *  License details are found in the file LICENSE.
 * \brief
 *  implement McKernel's sysfs files, IHK-Master side
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2016  RIKEN AICS
 */
/*
 * HISTORY:
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "../../config.h"
#include "mcctrl.h"
#include "sysfs_msg.h"

#define dprintk(...) do { if (0) printk(KERN_DEBUG __VA_ARGS__); } while (0)
#define wprintk(...) do { if (1) printk(KERN_WARNING __VA_ARGS__); } while (0)
#define eprintk(...) do { if (1) printk(KERN_ERR __VA_ARGS__); } while (0)

static ssize_t
show_int(struct sysfsm_ops *ops, void *instance, void *buf, size_t size)
{
	int *p = instance;

	return snprintf(buf, size, "%d\n", *p);
} /* show_int() */

struct sysfsm_ops show_int_ops = {
	.show = &show_int,
};

void setup_local_snooping_samples(ihk_os_t os)
{
	static long lvalue = 0xf123456789abcde0;
	static char *svalue = "string(local)";
	int error;
	struct sysfsm_bitmap_param param;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_d32, &lvalue, 0444, "/sys/test/local/d32");
	if (error) {
		panic("setup_local_snooping_samples: d32");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_d64, &lvalue, 0444, "/sys/test/local/d64");
	if (error) {
		panic("setup_local_snooping_samples: d64");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u32, &lvalue, 0444, "/sys/test/local/u32");
	if (error) {
		panic("setup_local_snooping_samples: u32");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u64, &lvalue, 0444, "/sys/test/local/u64");
	if (error) {
		panic("setup_local_snooping_samples: u64");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_s, svalue, 0444, "/sys/test/local/s");
	if (error) {
		panic("setup_local_snooping_samples: s");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444, "/sys/test/local/pbl");
	if (error) {
		panic("setup_local_snooping_samples: pbl");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pb, &param, 0444, "/sys/test/local/pb");
	if (error) {
		panic("setup_local_snooping_samples: pb");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u32K, &lvalue, 0444, "/sys/test/local/u32K");
	if (error) {
		panic("setup_local_snooping_samples: u32K");
	}

	return;
}

void setup_local_snooping_files(ihk_os_t os)
{
	struct ihk_cpu_info *info;
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);
	struct sysfsm_bitmap_param param;
	static unsigned long cpu_offline = 0x0;
	int i;
	int error;

	info = ihk_os_get_cpu_info(os);
	if (!info) {
		eprintk("mcctrl:ihk_os_get_cpu_info failed.\n");
		return;
	}

	memset(udp->cpu_online, 0, sizeof(udp->cpu_online));
	for (i = 0; i < info->n_cpus; i++) {
		udp->cpu_online[i / BITS_PER_LONG] = 
			udp->cpu_online[i / BITS_PER_LONG] | (1 << (i % BITS_PER_LONG));
	}

	param.nbits = CPU_LONGS * BITS_PER_LONG;
	param.ptr = udp->cpu_online;
	dprintk("mcctrl:setup_local_snooping_files: CPU_LONGS=%d, BITS_PER_LONG=%d\n", 
		CPU_LONGS, BITS_PER_LONG);

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/online");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/online");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/possible");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/possible");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/present");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/present");
	}

	param.nbits = BITS_PER_LONG;
	param.ptr = &cpu_offline;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/offline");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/offline");
	}

	return;
}

static void free_node_topology(struct mcctrl_usrdata *udp)
{
	struct node_topology *node;
	struct node_topology *next;

	list_for_each_entry_safe(node, next, &udp->node_topology_list, chain) {
		list_del(&node->chain);
		kfree(node);
	}

	return;
} /* free_node_topology() */

static void free_cpu_topology_one(struct mcctrl_usrdata *udp,
		struct cpu_topology *cpu)
{
	struct cache_topology *cache;
	struct cache_topology *next;

	list_for_each_entry_safe(cache, next, &cpu->cache_list, chain) {
		list_del(&cache->chain);
		kfree(cache);
	}

	kfree(cpu);
	return;
} /* free_cpu_topology_one() */

static void free_cpu_topology(struct mcctrl_usrdata *udp)
{
	struct cpu_topology *cpu;
	struct cpu_topology *next;

	list_for_each_entry_safe(cpu, next, &udp->cpu_topology_list, chain) {
		list_del(&cpu->chain);
		free_cpu_topology_one(udp, cpu);
	}

	return;
} /* free_cpu_topology() */

static void free_cpu_mapping(struct mcctrl_usrdata *udp)
{
	ihk_device_t dev = ihk_os_to_dev(udp->os);
	size_t size;

	size = udp->cpu_mapping_elems * sizeof(struct cpu_mapping);
	ihk_device_unmap_virtual(dev, udp->cpu_mapping, size);
	ihk_device_unmap_memory(dev, udp->cpu_mapping_pa, size);

	return;
} /* free_cpu_mapping() */

void free_topology_info(ihk_os_t os)
{
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);

	free_node_topology(udp);
	free_cpu_topology(udp);
	free_cpu_mapping(udp);

	return;
} /* free_topology_info() */

void reply_get_cpu_mapping(long req_pa)
{
	struct get_cpu_mapping_req *req = phys_to_virt(req_pa);

	req->busy = 0;
	wake_up(&req->wq);

	return;
} /* reply_get_cpu_mapping() */

static int get_cpu_mapping(struct mcctrl_usrdata *udp)
{
	int error;
	ihk_device_t dev = ihk_os_to_dev(udp->os);
	struct get_cpu_mapping_req *req = NULL;
	struct ikc_scd_packet packet;
	size_t size;

	dprintk("get_cpu_mapping(%p)\n", udp);

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		error = -ENOMEM;
		eprintk("mcctrl:get_cpu_mapping:kmalloc failed. %d\n", error);
		goto out;
	}

	req->busy = 1;
	req->error = -1;
	init_waitqueue_head(&req->wq);

	packet.msg = SCD_MSG_GET_CPU_MAPPING;
	packet.arg = virt_to_phys(req);

#define GET_CPU_MAPPING_CPU 0
	error = mcctrl_ikc_send(udp->os, GET_CPU_MAPPING_CPU, &packet);
	if (error) {
		eprintk("mcctrl:get_cpu_mapping:"
				"mcctrl_ikc_send failed. %d\n", error);
		goto out;
	}

	error = wait_event_interruptible(req->wq, !req->busy);
	if (error) {
		eprintk("mcctrl:get_cpu_mapping:"
				"wait_event_interruptible failed. %d\n", error);
		req = NULL;	/* XXX */
		goto out;
	}

	if (req->error) {
		error = req->error;
		eprintk("mcctrl:get_cpu_mapping:"
				"SCD_MSG_GET_CPU_MAPPING failed. %d\n", error);
		goto out;
	}

	size = req->buf_elems * sizeof(struct cpu_mapping);
	udp->cpu_mapping_elems = req->buf_elems;
	udp->cpu_mapping_pa = ihk_device_map_memory(dev, req->buf_rpa, size);
	udp->cpu_mapping = ihk_device_map_virtual(
			dev, udp->cpu_mapping_pa, size, NULL, 0);

	error = 0;
out:
	dprintk("get_cpu_mapping(%p): %d\n", udp, error);
	kfree(req);
	return error;
} /* get_cpu_mapping() */

static int hwid_to_cpu(struct mcctrl_usrdata *udp, int hw_id)
{
	int i;

	for (i = 0; i < udp->cpu_mapping_elems; ++i) {
		if (udp->cpu_mapping[i].hw_id == hw_id) {
			return udp->cpu_mapping[i].cpu_number;
		}
	}

	return -1;
}

static int translate_cpumap(struct mcctrl_usrdata *udp,
		cpumask_t *linmap, cpumask_t *mckmap)
{
	int error;
	ihk_device_t dev = ihk_os_to_dev(udp->os);
	int lincpu;
	int hw_id;
	int mckcpu;

	dprintk("translate_cpumap(%p,%p,%p)\n", udp, linmap, mckmap);
	cpumask_clear(mckmap);
	for_each_cpu(lincpu, linmap) {
		hw_id = ihk_device_linux_cpu_to_hw_id(dev, lincpu);
		if (hw_id < 0) {
			error = hw_id;
			eprintk("mcctrl:translate_cpumap:"
					"ihk_device_linux_cpu_to_hw_id failed."
					" %d\n", error);
			goto out;
		}

		mckcpu = hwid_to_cpu(udp, hw_id);
		if (mckcpu >= 0) {
			cpumask_set_cpu(mckcpu, mckmap);
		}
	}

	error = 0;
out:
	dprintk("translate_cpumap(%p,%p,%p): %d\n", udp, linmap, mckmap, error);
	return error;
} /* translate_cpumap() */

static struct cache_topology *get_cache_topology(struct mcctrl_usrdata *udp,
		struct cpu_topology *cpu_topo, struct ihk_cache_topology *saved)
{
	int error;
	struct cache_topology *topo = NULL;

	dprintk("get_cache_topology(%p,%p)\n", cpu_topo, saved);
	topo = kmalloc(sizeof(*topo), GFP_KERNEL);
	if (!topo) {
		error = -ENOMEM;
		eprintk("mcctrl:get_cache_topology:"
				"kmalloc failed. %d\n", error);
		goto out;
	}

	topo->saved = saved;

	error = translate_cpumap(udp, &topo->saved->shared_cpu_map,
			&topo->shared_cpu_map);
	if (error) {
		eprintk("mcctrl:get_cache_topology:"
				"translate_cpumap failed. %d\n", error);
		goto out;
	}

	error = 0;
out:
	if (error && !IS_ERR_OR_NULL(topo)) {
		kfree(topo);
	}
	dprintk("get_cache_topology(%p,%p): %d %p\n",
			cpu_topo, saved, error, topo);
	return (error)? ERR_PTR(error): topo;
} /* get_cache_topology() */

static struct cpu_topology *get_cpu_topology_one(struct mcctrl_usrdata *udp,
		int index)
{
	int error;
	ihk_device_t dev = ihk_os_to_dev(udp->os);
	struct cpu_topology *topology = NULL;
	struct cache_topology *cache;
	struct ihk_cache_topology *saved_cache;

	dprintk("get_cpu_topology_one(%p,%d)\n", udp, index);
	topology = kmalloc(sizeof(*topology), GFP_KERNEL);
	if (!topology) {
		error = -ENOMEM;
		eprintk("mcctrl:get_cpu_topology_one:"
				"kmalloc failed. %d\n", error);
		goto out;
	}

	INIT_LIST_HEAD(&topology->cache_list);
	topology->cpu_mapping = &udp->cpu_mapping[index];

	topology->saved = ihk_device_get_cpu_topology(
			dev, topology->cpu_mapping->hw_id);
	if (IS_ERR(topology->saved)) {
		error = PTR_ERR(topology->saved);
		eprintk("mcctrl:get_cpu_topology_one:"
				"ihk_device_get_cpu_topology failed. %d\n",
				error);
		goto out;
	}

	error = translate_cpumap(udp, &topology->saved->core_siblings,
			&topology->core_siblings);
	if (error) {
		eprintk("mcctrl:get_cpu_topology_one:"
				"translate_cpumap(core_siblings) failed."
				" %d\n", error);
		goto out;
	}

	error = translate_cpumap(udp, &topology->saved->thread_siblings,
			&topology->thread_siblings);
	if (error) {
		eprintk("mcctrl:get_cpu_topology_one:"
				"translate_cpumap(thread_siblings) failed."
				" %d\n", error);
		goto out;
	}

	list_for_each_entry(saved_cache,
			&topology->saved->cache_topology_list, chain) {
		cache = get_cache_topology(udp, topology, saved_cache);
		if (IS_ERR(cache)) {
			error = PTR_ERR(cache);
			eprintk("mcctrl:get_cpu_topology_one:"
					"get_cache_topology failed. %d\n",
					error);
			goto out;
		}

		list_add(&cache->chain, &topology->cache_list);
	}

	error = 0;
out:
	if (error && !IS_ERR_OR_NULL(topology)) {
		free_cpu_topology_one(udp, topology);
	}
	dprintk("get_cpu_topology_one(%p,%d): %d %p\n",
			udp, index, error, topology);
	return (error)? ERR_PTR(error): topology;
} /* get_cpu_topology_one() */

static int get_cpu_topology(struct mcctrl_usrdata *udp)
{
	int error;
	int index;
	struct cpu_topology *topology;

	dprintk("get_cpu_topology(%p)\n", udp);
	for (index = 0; index < udp->cpu_mapping_elems; ++index) {
		topology = get_cpu_topology_one(udp, index);
		if (IS_ERR(topology)) {
			error = PTR_ERR(topology);
			eprintk("mcctrl:get_cpu_topology:"
					"get_cpu_topology_one failed. %d\n",
					error);
			goto out;
		}

		list_add(&topology->chain, &udp->cpu_topology_list);
	}

	error = 0;
out:
	dprintk("get_cpu_topology(%p): %d\n", udp, error);
	return error;
} /* get_cpu_topology() */

static void setup_one_cache_files(struct mcctrl_usrdata *udp,
		struct cpu_topology *cpu, struct cache_topology *cache)
{
	char *prefix = "/sys/devices/system/cpu";
	int cpu_number = cpu->cpu_mapping->cpu_number;
	int index = cache->saved->index;
	struct sysfsm_bitmap_param param;

	dprintk("setup_one_cache_files(%p,%p,%p)\n", udp, cpu, cache);

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d64,
			&cache->saved->level, 0444,
			"%s/cpu%d/cache/index%d/level",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_s,
			cache->saved->type, 0444,
			"%s/cpu%d/cache/index%d/type",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_s,
			cache->saved->size_str, 0444,
			"%s/cpu%d/cache/index%d/size",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d64,
			&cache->saved->coherency_line_size, 0444,
			"%s/cpu%d/cache/index%d/coherency_line_size",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d64,
			&cache->saved->number_of_sets, 0444,
			"%s/cpu%d/cache/index%d/number_of_sets",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d64,
			&cache->saved->physical_line_partition, 0444,
			"%s/cpu%d/cache/index%d/physical_line_partition",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d64,
			&cache->saved->ways_of_associativity, 0444,
			"%s/cpu%d/cache/index%d/ways_of_associativity",
			prefix, cpu_number, index);

	param.nbits = nr_cpumask_bits;
	param.ptr = &cache->shared_cpu_map;

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pb, &param, 0444,
			"%s/cpu%d/cache/index%d/shared_cpu_map",
			prefix, cpu_number, index);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
			"%s/cpu%d/cache/index%d/shared_cpu_list",
			prefix, cpu_number, index);

	dprintk("setup_one_cache_files(%p,%p,%p):\n", udp, cpu, cache);
	return;
} /* setup_one_cache_files() */

static void setup_one_cpu_files(struct mcctrl_usrdata *udp,
		struct cpu_topology *cpu)
{
	char *prefix = "/sys/devices/system/cpu";
	int cpu_number = cpu->cpu_mapping->cpu_number;
	struct sysfsm_bitmap_param param;
	struct cache_topology *cache;

	dprintk("setup_one_cpu_files(%p,%p)\n", udp, cpu);

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d32,
			&cpu->saved->physical_package_id, 0444,
			"%s/cpu%d/topology/physical_package_id",
			prefix, cpu_number);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_d32,
			&cpu->saved->core_id, 0444,
			"%s/cpu%d/topology/core_id",
			prefix, cpu_number);

	param.nbits = nr_cpumask_bits;
	param.ptr = &cpu->core_siblings;

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pb, &param, 0444,
			"%s/cpu%d/topology/core_siblings",
			prefix, cpu_number);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
			"%s/cpu%d/topology/core_siblings_list",
			prefix, cpu_number);

	param.nbits = nr_cpumask_bits;
	param.ptr = &cpu->thread_siblings;

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pb, &param, 0444,
			"%s/cpu%d/topology/thread_siblings",
			prefix, cpu_number);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
			"%s/cpu%d/topology/thread_siblings_list",
			prefix, cpu_number);

	list_for_each_entry(cache, &cpu->cache_list, chain) {
		setup_one_cache_files(udp, cpu, cache);
	}

	dprintk("setup_one_cpu_files(%p,%p):\n", udp, cpu);
	return;
} /* setup_one_cpu_files() */

static void setup_cpu_files(struct mcctrl_usrdata *udp)
{
	int error;
	struct cpu_topology *cpu;

	dprintk("setup_cpu_file(%p)\n", udp);
	error = get_cpu_mapping(udp);
	if (error) {
		eprintk("mcctrl:setup_cpu_files:"
				"get_cpu_mapping failed. %d\n", error);
		goto out;
	}

	error = get_cpu_topology(udp);
	if (error) {
		eprintk("mcctrl:setup_cpu_files:"
				"get_cpu_topology failed. %d\n", error);
		goto out;
	}

	list_for_each_entry(cpu, &udp->cpu_topology_list, chain) {
		setup_one_cpu_files(udp, cpu);
	}
	error = 0;
out:
	dprintk("setup_cpu_file(%p):\n", udp);
	return;
} /* setup_cpu_files() */

static struct node_topology *get_one_node_topology(struct mcctrl_usrdata *udp,
		struct ihk_node_topology *saved)
{
	int error;
	struct node_topology *node = NULL;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		error = -ENOMEM;
		eprintk("mcctrl:get_one_node_topology:"
				"kmalloc failed. %d\n", error);
		goto out;
	}

	node->saved = saved;

	error = translate_cpumap(udp, &node->saved->cpumap, &node->cpumap);
	if (error) {
		eprintk("mcctrl:get_one_node_topology:"
				"translate_cpumap failed. %d\n", error);
		goto out;
	}

	error = 0;
out:
	if (error && !IS_ERR_OR_NULL(node)) {
		kfree(node);
	}
	return (error)? ERR_PTR(error): node;
} /* get_one_node_topology() */

static int get_node_topology(struct mcctrl_usrdata *udp)
{
	int error;
	ihk_device_t dev = ihk_os_to_dev(udp->os);
	int node;
	struct ihk_node_topology *saved;
	struct node_topology *topology;

	dprintk("get_node_topology(%p)\n", udp);
	for (node = 0; ; ++node) {
		saved = ihk_device_get_node_topology(dev, node);
		if (IS_ERR(saved)) {
			break;
		}
		if (!saved) {
			continue;
		}

		topology = get_one_node_topology(udp, saved);
		if (IS_ERR(topology)) {
			error = PTR_ERR(topology);
			eprintk("mcctrl:get_node_topology:"
					"get_one_node_topology failed. %d\n",
					error);
			goto out;
		}

		list_add(&topology->chain, &udp->node_topology_list);
	}

	error = 0;
out:
	dprintk("get_node_topology(%p): %d\n", udp, error);
	return error;
} /* get_node_topology() */

static int setup_node_files(struct mcctrl_usrdata *udp)
{
	int error;
	struct node_topology *p;
	struct sysfsm_bitmap_param param;

	dprintk("setup_node_files(%p)\n", udp);
	error = get_node_topology(udp);
	if (error) {
		eprintk("mcctrl:setup_node_files:"
				"get_node_topology failed. %d\n", error);
		goto out;
	}

	list_for_each_entry(p, &udp->node_topology_list, chain) {
		param.nbits = nr_cpumask_bits;
		param.ptr = &p->cpumap;

		sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pb, &param, 0444,
				"/sys/devices/system/node/node%d/cpumap",
				p->saved->node_number);
		sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
				"/sys/devices/system/node/node%d/cpulist",
				p->saved->node_number);
	}

	error = 0;
out:
	dprintk("setup_node_files(%p): %d\n", udp, error);
	return error;
} /* setup_node_files() */

static int read_file(void *buf, size_t size, char *fmt, va_list ap)
{
	int error;
	int er;
	char *filename = NULL;
	int n;
	struct file *fp = NULL;
	loff_t off;
	mm_segment_t ofs;
	ssize_t ss;

	dprintk("read_file(%p,%ld,%s,%p)\n", buf, size, fmt, ap);
	filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!filename) {
		error = -ENOMEM;
		eprintk("mcctrl:read_file:kmalloc failed. %d\n", error);
		goto out;
	}

	n = vsnprintf(filename, PATH_MAX, fmt, ap);
	if (n >= PATH_MAX) {
		error = -ENAMETOOLONG;
		eprintk("mcctrl:read_file:vsnprintf failed. %d\n", error);
		goto out;
	}

	fp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		error = PTR_ERR(fp);
		eprintk("mcctrl:read_file:filp_open failed. %d\n", error);
		goto out;
	}

	off = 0;
	ofs = get_fs();
	set_fs(KERNEL_DS);
	ss = vfs_read(fp, buf, size, &off);
	set_fs(ofs);
	if (ss < 0) {
		error = ss;
		eprintk("mcctrl:read_file:vfs_read failed. %d\n", error);
		goto out;
	}
	if (ss >= size) {
		error = -ENOSPC;
		eprintk("mcctrl:read_file:buffer overflow. %d\n", error);
		goto out;
	}
	*(char *)(buf + ss) = '\0';

	error = 0;
out:
	if (!IS_ERR_OR_NULL(fp)) {
		er = filp_close(fp, NULL);
		if (er) {
			eprintk("mcctrl:read_file:"
					"filp_close failed. %d\n", error);
		}
	}
	kfree(filename);
	dprintk("read_file(%p,%ld,%s,%p): %d\n", buf, size, fmt, ap, error);
	return error;
} /* read_file() */

static int read_long(long *valuep, char *fmt, ...)
{
	int error;
	char *buf = NULL;
	va_list ap;
	int n;

	dprintk("read_long(%p,%s)\n", valuep, fmt);
	buf = (void *)__get_free_pages(GFP_KERNEL, 0);
	if (!buf) {
		error = -ENOMEM;
		eprintk("mcctrl:read_long:"
				"__get_free_pages failed. %d\n", error);
		goto out;
	}

	va_start(ap, fmt);
	error = read_file(buf, PAGE_SIZE, fmt, ap);
	va_end(ap);
	if (error) {
		eprintk("mcctrl:read_long:read_file failed. %d\n", error);
		goto out;
	}

	n = sscanf(buf, "%ld", valuep);
	if (n != 1) {
		error = -EIO;
		eprintk("mcctrl:read_long:sscanf failed. %d\n", error);
		goto out;
	}

	error = 0;
out:
	free_pages((long)buf, 0);
	dprintk("read_long(%p,%s): %d\n", valuep, fmt, error);
	return error;
} /* read_long() */

#ifdef MCCTRL_KSYM_sys_readlink
static ssize_t (*mcctrl_sys_readlink)(const char *path, char *buf,
		size_t bufsiz)
#if MCCTRL_KSYM_sys_readlink
	= (void *)MCCTRL_KSYM_sys_readlink;
#else
	= &sys_readlink;
#endif
#endif

static int read_link(char *buf, size_t bufsize, char *fmt, ...)
{
	int error;
	char *filename = NULL;
	va_list ap;
	int n;
	mm_segment_t old_fs;
	ssize_t ss;

	dprintk("read_link(%p,%#lx,%s)\n", buf, bufsize, fmt);
	filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!filename) {
		error = -ENOMEM;
		eprintk("mcctrl:read_link:kmalloc failed. %d\n", error);
		goto out;
	}

	va_start(ap, fmt);
	n = vsnprintf(filename, PATH_MAX, fmt, ap);
	va_end(ap);
	if (n >= PATH_MAX) {
		error = -ENAMETOOLONG;
		eprintk("mcctrl:read_link:snprintf failed. %d\n", error);
		goto out;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ss = mcctrl_sys_readlink(filename, buf, bufsize);
	set_fs(old_fs);
	if (ss < 0) {
		error = ss;
		eprintk("mcctrl:read_link:sys_readlink failed. %d\n", error);
		goto out;
	}
	if (ss >= bufsize) {
		error = -ENOSPC;
		eprintk("mcctrl:read_link:linkname too long. %d\n", error);
		goto out;
	}
	buf[ss] = '\0';

	error = 0;
out:
	kfree(filename);
	dprintk("read_link(%p,%#lx,%s): %d\n", buf, bufsize, fmt, error);
	return error;
} /* read_link() */

static int setup_one_pci(void *arg0, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned d_type)
{
	struct mcctrl_usrdata *udp = arg0;
	int error;
	char *buf = NULL;
	long node;
	struct sysfsm_bitmap_param param;

	dprintk("setup_one_pci(%p,%s,%d,%#lx,%#lx,%d)\n",
			arg0, name, namlen, (long)offset, (long)ino, d_type);
	if (namlen != 12) {
		error = 0;
		goto out;
	}

	buf = (void *)__get_free_pages(GFP_KERNEL, 0);
	if (!buf) {
		error = -ENOMEM;
		eprintk("mcctrl:setup_one_pci:"
				"__get_free_pages failed. %d\n", error);
		goto out;
	}

	error = read_long(&node, "/sys/bus/pci/devices/%s/numa_node", name);
	if (error) {
		eprintk("mcctrl:setup_one_pci:read_long failed. %d\n", error);
		goto out;
	}

	error = read_link(buf, PAGE_SIZE, "/sys/bus/pci/devices/%s", name);
	if (error) {
		eprintk("mcctrl:setup_one_pci:read_link failed. %d\n", error);
		goto out;
	}

	if (strncmp(buf, "../../../devices/", 17)) {
		error = -ENOENT;
		eprintk("mcctrl:setup_one_pci:"
				"realpath is not /sys/devices. %d\n", error);
		goto out;
	}

	param.ptr = &udp->cpu_online;
	param.nbits = nr_cpumask_bits;
	if (node >= 0) {
		struct node_topology *node_topo;

		list_for_each_entry(node_topo,
				&udp->node_topology_list, chain) {
			if (node_topo->saved->node_number == node) {
				param.ptr = &node_topo->cpumap;
				param.nbits = nr_cpumask_bits;
				break;
			}
		}
	}

	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pb, &param, 0444,
			"/sys/%s/local_cpus", buf+9);
	sysfsm_createf(udp->os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
			"/sys/%s/local_cpulist", buf+9);

	error = 0;
out:
	free_pages((long)buf, 0);
	dprintk("setup_one_pci(%p,%s,%d,%#lx,%#lx,%d): %d\n",
			arg0, name, namlen, (long)offset, (long)ino, d_type,
			error);
	return error;
} /* setup_one_pci() */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
typedef int (*mcctrl_filldir_t)(void *buf, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned d_type);

struct mcctrl_filler_args {
	struct dir_context ctx;
	mcctrl_filldir_t filler;
	void *buf;
};

static int mcctrl_filler(struct dir_context *ctx, const char *name,
		int namlen, loff_t offset, u64 ino, unsigned d_type)
{
	struct mcctrl_filler_args *args
		= container_of(ctx, struct mcctrl_filler_args, ctx);

	return (*args->filler)(args->buf, name, namlen, offset, ino, d_type);
} /* mcctrl_filler() */

static inline int mcctrl_vfs_readdir(struct file *file,
		mcctrl_filldir_t filler, void *buf)
{
	struct mcctrl_filler_args args = {
		.ctx.actor = &mcctrl_filler,
		.filler = (void *)filler,
		.buf = buf,
	};

	return iterate_dir(file, &args.ctx);
} /* mcctrl_vfs_readdir() */
#else
static inline int mcctrl_vfs_readdir(struct file *file, filldir_t filler,
		void *buf)
{
	return vfs_readdir(file, filler, buf);
} /* mcctrl_vfs_readdir() */
#endif

static int setup_pci_files(struct mcctrl_usrdata *udp)
{
	int error;
	int er;
	struct file *fp = NULL;

	dprintk("setup_pci_files(%p)\n", udp);
	fp = filp_open("/sys/bus/pci/devices", O_DIRECTORY, 0);
	if (IS_ERR(fp)) {
		error = PTR_ERR(fp);
		eprintk("mcctrl:setup_pci_files:filp_open failed. %d\n", error);
		goto out;
	}

	error = mcctrl_vfs_readdir(fp, &setup_one_pci, udp);
	if (error) {
		eprintk("mcctrl:setup_pci_files:"
				"mcctrl_vfs_readdir failed. %d\n", error);
		goto out;
	}

	error = 0;
out:
	if (!IS_ERR_OR_NULL(fp)) {
		er = filp_close(fp, NULL);
		if (er) {
			eprintk("mcctrl:setup_pci_files:"
					"filp_close failed. %d\n", er);
		}
	}
	dprintk("setup_pci_files(%p): %d\n", udp, error);
	return error;
} /* setup_pci_files() */

void setup_sysfs_files(ihk_os_t os)
{
	static int a_value = 35;
	int error;
	struct sysfs_handle handle;
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);

	error = sysfsm_mkdirf(os, NULL, "/sys/test/x.dir");
	if (error) {
		panic("sysfsm_mkdir(x.dir)");
	}

	error = sysfsm_createf(os, &show_int_ops, &a_value, 0444,
			"/sys/test/a.dir/a_value");
	if (error) {
		panic("sysfsm_createf");
	}

	error = sysfsm_lookupf(os, &handle, "/sys/test/%s", "a.dir");
	if (error) {
		panic("sysfsm_lookupf(a.dir)");
	}

	error = sysfsm_symlinkf(os, handle, "/sys/test/%c.dir", 'L');
	if (error) {
		panic("sysfsm_symlinkf");
	}

	error = sysfsm_unlinkf(os, 0, "/sys/test/%s.dir", "x");
	if (error) {
		panic("sysfsm_unlinkf");
	}

	setup_local_snooping_samples(os);
	setup_local_snooping_files(os);
	setup_cpu_files(udp);
	setup_node_files(udp);
	setup_pci_files(udp);

	return;
} /* setup_files() */

/**** End of File ****/
