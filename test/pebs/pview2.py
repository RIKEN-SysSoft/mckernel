#!/usr/bin/python3.6
#import matplotlib
#matplotlib.use('Agg')


from struct import *
import sys, re, argparse
from math import log
from math import floor

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.ticker as ticker
import numpy as np; np.random.seed(0)
import svgwrite
from svgwrite import cm, mm, rgb, deg

from multiprocessing import Pool, cpu_count


SVG_WIDTH = "100cm"
SVG_HEIGHT = "100cm"
SVG_SIZE = (SVG_WIDTH, SVG_HEIGHT)
CSS_STYLES = """
    .background { fill: white; }
    .line { stroke: firebrick; stroke-width: .1mm; }
    .mem { fill: white; }
    .whitesquare { fill: hotpink; }
"""

vb = 0
maxHeatRange = 255

def check_power_of_two(val):
	ival = int(val)
	if (ival & (ival-1)) == 0:
		return int(log(ival,2))
	else:
		raise argparse.ArgumentTypeError("%s is not a power of two" % val)

def check_granularity(val):
	if val == "page":
		return 12
	else:
		return check_power_of_two(val)

def check_hex_address(val):
	try:
		return int(val,16)
	except:
		raise argparse.ArgumentTypeError("%s address format not understood" % val)

def parse_arguments():
	"""Parse script arguments"""
	global vb

	parser = argparse.ArgumentParser()

	parser.add_argument('-f', '--file', action='store', dest='file',
			default="pebs.out",
			help="PEBS dump file to analyze. Default is pebs.out")
	parser.add_argument('-s', '--size', action='store', dest='size',
			help="""Size of the memory region: D1xD2 e.g. 10x20.
			This determines the layout of the memory area
			displayed.""")
	parser.add_argument('-g', '--granularity', action='store',
			type=check_granularity, dest='granularity', default=0,
			help="""Granularity of displayed blocks of memory. By
			default are bytes. The value must be a multiple of two.
			Set "page" for page-size granularity """)
	parser.add_argument('-S', '--page-shift', action='store', type=int, default=12)
	parser.add_argument('-i', '--first-address', action='store',
			type=check_hex_address, dest='firstAddress', default=0,
			help="""First virtual address of the buffer in hex. The
			first address is needed when the user memory segment is
			not aligned to the buffer column size (in C ordering).
			This is only useful when used in combination with
			--size.""")
	parser.add_argument('-v', '--verbose', action='count', default=0,
			help="Increase output verbosity")
	parser.add_argument('-a', '--accumulate', action='store_true',
			help="""Each timestamp svg will show the data accesses
			of the previous timestamps.""")
	parser.add_argument('-r', '--histograms', action='store_true',
			help="""Plot memory address histograms. Useful to
			detect outlayers""")
	parser.add_argument('-t', '--timeline', action='store_true',
			help="""Plot memory address timeline. This ignores the
			--size layout and --granularity.""")
	parser.add_argument('-o', '--outlier', action='store', type=int,
			default=2, help="""Set outlier filtering parameter.
			Default is 2. Set to 0 to skip outlier filtering
			phase""")

	args = parser.parse_args()

	if args.size != None:
		args.size = [int(x) for x in args.size.split("x")]

	if args.timeline:
		args.granularity = 12


	vb = args.verbose

	return args

def getl(val, es):
	"""Cast binary data into an unsigned long long"""
	if (len(val) == es):
		return unpack('Q', val)[0];
	else:
		return None

def tohex(val):
	"""Convert value to hexadecimal string"""
	if isinstance(val, list):
		return [tohex(x) for x in val]
	else:
		return format(val, '02x')

def readPebsDumpV2(filename):
	"""Read PEBS dump file provided in filename argument"""

	# State machine states
	mmap = 0
	umap = 1
	pebs = 2
	end  = 3
	state = mmap

	es = 8
	records = []
	tss = []
	watermark=0xffffffffffffffff

	mmaps = []
	munmaps = []
	ts_prev = 0

	with open(filename, mode='rb') as file:
		err = 0
		while True:
			elem = getl(file.read(es), es)
			if state == mmap:
				if elem == watermark:
					state = umap
					continue
				ts     = elem
				start  = getl(file.read(es), es)
				length = getl(file.read(es), es)
				mmaps.append([start, length, ts])
			elif state == umap:
				if elem == watermark:
					state = pebs
					continue
				ts     = elem
				start  = getl(file.read(es), es)
				length = getl(file.read(es), es)
				munmaps.append([start, length, ts])
			elif state == pebs:
				if (elem == watermark):
					ts = getl(file.read(es), es)
					if ts == None:
						err = 1
						break
					nelem = getl(file.read(es), es)
					if nelem == None:
						err = 1
						break

					print("reading {} addresses for ts: {}, elapsed: {}".format(nelem, ts, int(ts) - ts_prev))
					ts_prev = int(ts)
					record = file.read(es*nelem)
					addr = unpack(str(nelem)+'Q', record)

					if (len(addr) != nelem):
						err = 1
						break

					records.append(np.array(addr))
					tss.append(ts)
				elif (elem == None):
					break

	return tss, mmaps, munmaps, records


def readPebsDump(filename):
	"""Read PEBS dump file provided in filename argument"""
	es = 8
	records = []
	tss = []
	watermark=0xffffffffffffffff

	with open(filename, mode='rb') as file:
		err = 0
		while True:
			elem = getl(file.read(es), es)
			if (elem == watermark):
				ts = getl(file.read(es), es)
				if ts == None:
					err = 1
					break
				nelem = getl(file.read(es), es)
				if nelem == None:
					err = 1
					break
				print("reading {} addresses for ts: {}".format(nelem, ts))
				record = file.read(es*nelem)
				addr = unpack(str(nelem)+'Q', record)

				if (len(addr) != nelem):
					err = 1
					break

				records.append(np.array(addr))
				tss.append(ts)
			elif (elem == None):
				break
	return tss, records

def updateBoundBox(boundbox, point):
	""" Update bounding box with new point"""
	if point[0] < boundbox[0]:
		boundbox[0] = point[0]
	elif point[0] > boundbox[2]:
		boundbox[2] = point[0]

	if point[1] < boundbox[1]:
		boundbox[1] = point[1]
	elif point[1] > boundbox[3]:
		boundbox[3] = point[1]

def reject_outliers(data, m = 2.):
	"""Remove outlier in the provided data set based on the m argument"""
	m = float(m)
	d = np.abs(data - np.median(data))
	mdev = np.median(d)
	s = d/mdev if mdev else 0.
	return data[s<m]


def pebsData2xaddr_yaddr(records, granularity, range_size):
	maxaddr = 0
	minaddr = 0xffffffffffffffff
	
	max_heat_cnt = 0
	max_heat_paddr = 0
	heatmaps = {}
	for ts, record in enumerate(records):
		if ts not in heatmaps:
			heatmaps[ts] = {}

		for i, addr in enumerate(record):
			paddr = addr & (~((1 << granularity) - 1))
			if heatmaps[ts].get(paddr) == None:
				heatmaps[ts][paddr] = 1
			else:
				heatmaps[ts][paddr] += 1

			if heatmaps[ts][paddr] > max_heat_cnt:
				max_heat_paddr = paddr
				max_heat_cnt = heatmaps[ts][paddr]

	maxaddr = max_heat_paddr + range_size
	minaddr = max_heat_paddr - range_size
	print("max_heat_paddr: {}, heat: {}, range: {}-{}:{}".format(
		hex(max_heat_paddr), max_heat_cnt, hex(minaddr), hex(maxaddr), maxaddr - minaddr))

	xaddr = []
	yaddr = []
	for ts in sorted(heatmaps.keys()):
		heatmap = heatmaps[ts]
		for paddr in heatmap.keys():
			if (paddr < minaddr or paddr >= maxaddr):
				continue

			for i in range(0, heatmap[paddr]):
				yaddr.append(paddr)
				xaddr.append(ts)

	return xaddr, yaddr, len(heatmaps.keys()), (maxaddr - minaddr) >> granularity

def pebsData2heatmap(records, page_shift, range_size):
	maxaddr = 0
	minaddr = 0xffffffffffffffff
	prev_ts = 0
	
	max_heat_cnt = 0
	max_heat_paddr = 0
	heatmaps = [0 for x in range(len(records))]
	for ts, record in enumerate(records):
		heatmaps[ts] = {}
		#if prev_ts != 0:
		#	print("elapsed cycles: {}".format(int(ts) - int(prev_ts)))
		prev_ts = ts

		for i, addr in enumerate(record):
			paddr = addr & (~((1 << page_shift) - 1))
			if heatmaps[ts].get(paddr) == None:
				heatmaps[ts][paddr] = 1
			else:
				heatmaps[ts][paddr] += 1

			if heatmaps[ts][paddr] > max_heat_cnt:
				max_heat_paddr = paddr
				max_heat_cnt = heatmaps[ts][paddr]

	maxaddr = max_heat_paddr + range_size
	minaddr = max_heat_paddr - range_size
	print("max_heat_paddr: {}, heat: {}, range: {}-{}:{}".format(
		hex(max_heat_paddr), max_heat_cnt, hex(minaddr), hex(maxaddr), maxaddr - minaddr))
	ytickvals = np.arange(minaddr, maxaddr, (1 << page_shift))
	ytickslabels = []
	for t in ytickvals:
		ytickslabels.append("{}".format(hex(t)))

	nr_addresses = (maxaddr - minaddr) >> page_shift
	print("nr addresses: {}, ytickslabels[0]: {}, ytickslabels[{}]: {}".format(
		nr_addresses, ytickslabels[0], nr_addresses - 1, ytickslabels[nr_addresses - 1]))

	hmap = np.zeros((nr_addresses, len(records)))

	for ind, heatmap in enumerate(heatmaps):
		for paddr in heatmap.keys():
			if (paddr < minaddr or paddr >= maxaddr):
				continue

			hmap[(paddr - minaddr) >> page_shift][ind] = heatmap[paddr]

	return hmap, ytickvals, ytickslabels, minaddr


def formatPebsData(records, firstAddress, granularity, size, outlier):
	"""Format PEBS data for plotting"""

	maxaddr = 0
	minaddr = 0xffffffffffffffff
	for i in range(len(records)):
		if outlier != 0:
			records[i] = reject_outliers(records[i], outlier)
		records[i] = (records[i] - firstAddress) >> granularity
		maxaddr = max(np.amax(records[i]),maxaddr)
		minaddr = min(np.amin(records[i]),minaddr)

	if size == None:
		size = [1, 1]

	# Initialize Bounding Box
	addr = records[0][0]
	svg_x = addr%size[0]
	svg_y = addr//size[0]
	point = [svg_x, svg_y]
	boundbox = [svg_x, svg_y, svg_x, svg_y]

	# If firstAddress, origin is at 0,0. Otherwise the origin is the
	# first point of the bounding box so we don't need to do anything.
	if firstAddress != 0:
		updateBoundBox(boundbox, [0, 0])

	heatmaps = [0 for x in range(len(records))]
	for ts, record in enumerate(records):
		heatmaps[ts] = {}
		for i, addr in enumerate(record):
			if heatmaps[ts].get(addr) == None:
				svg_x = addr%size[0]
				svg_y = addr//size[0]
				point = [svg_x, svg_y]
				count = 1
				heat = 0
				heatmaps[ts][addr] = [count, point, heat]
				updateBoundBox(boundbox, point)
			else:
				heatmaps[ts][addr][0] += 1

	# Infere last address point and add it to the bounding box.
	if firstAddress != 0:
		last_x = size[0] - 1
		last_y = size[1] - 1
	else:
		last_x = boundbox[0] + size[0] - 1
		last_y = boundbox[1] + size[1] - 1
	point = [last_x, last_y]
	updateBoundBox(boundbox, point)

	if vb > 0:
		print("timesteps:", len(heatmaps))
		print("size:", size)
		print("granularity: ", granularity)
		print("min addr: ", tohex(minaddr))
		print("max addr: ", tohex(maxaddr))
		print("boundbox: ", boundbox)
		print("  - xmax: ", boundbox[2]-boundbox[0])
		print("  - ymax: ", boundbox[3]-boundbox[1])

	return heatmaps, boundbox, minaddr

def draw_mem(heatmap, dwg, boundbox):
	"""Draw memory accesses on the dwg object"""
	def group(classname):
		return dwg.add(dwg.g(class_=classname))

	mem = group("mem")

	for k, v in heatmap.items():
		x0 = int(v[1][0])
		y0 = int(v[1][1])
		if vb == 3:
			print("Insert access (",x0,",",y0,") accesses:", v[0], "color:",v[2])
		access = dwg.rect(insert=(x0, y0), size=(1, 1))
		mem.add(access)
		u = dwg.use(access, fill=rgb(v[2], 0, 0))
		dwg.add(u)

def svgplot(filename, heatmap, boundbox):
	"""Write provided heatmap into an SVG image file"""
	if vb > 0:
		print(" - plotting", filename)

	x0   = int(boundbox[0])
	y0   = int(boundbox[1])
	xlen = int(boundbox[2] - boundbox[0]) + 1
	ylen = int(boundbox[3] - boundbox[1]) + 1

	dwg = svgwrite.Drawing(filename+'.svg', size=SVG_SIZE)
	dwg.viewbox(x0, y0, xlen, ylen)
	dwg.defs.add(dwg.style(CSS_STYLES))

	# set background
	#dwg.add(dwg.rect(insert=(x0, y0), size=('100%','100%'), class_='background'))
	dwg.add(dwg.rect(insert=(x0, y0), size=(xlen, ylen), class_='background'))
	draw_mem(heatmap, dwg, boundbox)
	dwg.save()

def plotHeatMaps(fileprefix, heatmaps, boundbox):
	"""Plot all provided heatmaps"""
	if vb > 0:
		print("Plotting", len(heatmaps), "timestamps")
	for ts, heatmap in enumerate(heatmaps):
		filename='pebs_' + str(ts)

		svgplot(filename, heatmap, boundbox)

def plotHeatMapsPar(fileprefix, heatmaps, boundbox):
	"""Plot all provided heatmaps in parallel"""
	ncpus = cpu_count()
	print("number of cpus:", ncpus)
	pool = Pool(processes=ncpus)
	if vb > 0:
		print("Plotting", len(heatmaps), "timestamps")
	args = []
	for ts, heatmap in enumerate(heatmaps):
		filename='pebs_' + str(ts)
		args.append([filename,heatmap,boundbox])

	pool.starmap(svgplot, args)

def accumulateAddresses(heatmaps):
	""" Accumulates data accesses counts of heatmap i to heatmap i+1.
	Returns the maximum and minimum heat boundaries """

	prev = heatmaps[0]
	minheat, maxheat = calcHeatBoundaries([prev])
	for heatmap in heatmaps[1:]:
		for k, v in prev.items():
			if heatmap.get(k) == None:
				heatmap[k] = prev[k]
			else:
				heatmap[k][0] += prev[k][0]
				if v[0] > maxheat:
					maxheat = v[0]
				elif v[0] < minheat:
					minheat = v[0]
		prev = heatmap
	return minheat, maxheat

def calcHeatBoundaries(heatmaps):
	""" Calculate minimum and maximum heat boundaries """
	minheat = list(heatmaps[0].values())[0][0]
	maxheat = 0

	for heatmap in heatmaps:
		for k, v in heatmap.items():
			if v[0] > maxheat:
				maxheat = v[0]
			elif v[0] < minheat:
				minheat = v[0]

	return minheat, maxheat

def calcHeatColor(heatmaps, minheat, maxheat):
	"""Calculate the heat color for each data access based on the minimum
	(minheat) and maximum (maxheat) number of data accesses"""
	for heatmap in heatmaps:
		for k, v in heatmap.items():
			heatmap[k][2] = int(round((maxHeatRange*(v[0]-minheat))/maxheat))

def plotHistograms(records):
	"""Plot histograms of memory accesses on files"""
	if vb > 0:
		print("Plotting", len(records), "histograms")
	for ts, record in enumerate(records):
		if vb > 0:
			print(" - plotting histogram",ts)
		plt.hist(record, bins=30)
		plt.ylabel('Memory Accesses')
		#plt.show()
		plt.savefig("pebs_hist_"+str(ts)+".png")
		plt.clf()

def plotHeatTimeline(heatmaps, boundbox, minaddr):
	"""Plot heatmaps in a timeline basis, all in a single image"""
	naddr = (boundbox[2]-boundbox[0]+1)*(boundbox[3]-boundbox[1]+1)
	print("Allocating numpy array of", naddr, "x", len(heatmaps))
	timeline = np.zeros((naddr,len(heatmaps)))
	print("Processing",len(heatmaps),"timesteps for timeline")
	for ts, heatmap in enumerate(heatmaps):
		print(" - processing timestep:",ts)
		for pair in sorted(heatmap.items()):
			addr = pair[0]-minaddr
			naccess = pair[1][0]
			timeline[addr][ts] = naccess
	plt.matshow(timeline, interpolation='None', aspect="auto")
	plt.title("PEBS Memory Access Timeline")
	plt.xlabel("Time")
	plt.ylabel("Per Page Accesses")
	plt.show()

def to_hex(x, pt):
    return '%x' % int(x)


class AddressFormatter(ticker.Formatter):
	offset = 0
	def __init__(self, offset, granularity):
		self.offset = offset
		self.granularity = granularity

	def __call__(self, x, pos = None):
		return '0x%x' % int(self.offset + (int(x) << self.granularity))



if __name__ == '__main__':
	args = parse_arguments()
	range_size = 40 * 1024**2

	tss, mmaps, munmaps, records = readPebsDumpV2(args.file)
	hmap, yticks, ytickslabels, minaddr = pebsData2heatmap(records, args.page_shift, range_size)
	fig, ax = plt.subplots()
	cax = ax.imshow(hmap, cmap='hot', interpolation='none')
	axes = plt.gca()
	print("len(ytickslabels): {}, hmap.shape[0]: {}".format(len(ytickslabels), hmap.shape[0]))
	fmt = AddressFormatter(minaddr, args.page_shift)
	ax.get_yaxis().set_major_formatter(fmt)

	plt.show()
	
	exit(0)

