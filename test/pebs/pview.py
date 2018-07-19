#!/usr/bin/python3.6
#import matplotlib
#matplotlib.use('Agg')


from struct import *
import sys, re, argparse
from argparse import RawTextHelpFormatter
from math import log, gcd
from functools import reduce


import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.ticker as ticker
from matplotlib.collections import PatchCollection

from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure

from scipy.sparse import coo_matrix

import numpy as np; np.random.seed(0)
import svgwrite
from svgwrite import cm, mm, rgb, deg

import seaborn as sns; sns.set()

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


class AddressSpace:

	class AddressSpaceFormatter(ticker.Formatter):
		offset = 0
		gran = 0
		def __init__(self, gran, offset):
			self.offset = offset
			self.gran = gran

		def __call__(self, x, pos = None):
			return '%x' % int((int(x) << self.gran) + (self.offset<<self.gran))

	vmas = None
	tss = None
	ntss = 0
	maxaddr = 0
	minaddr = 0xffffffffffffffff
	freq = 1
	gran = 12

	minAccess = sys.maxsize
	maxAccess = 0

	timeScale = "ms"
	cmap = "rainbow"

	def __init__(self, tss, mmaps, munmaps, records, freq, gran):
		self.tss  = tss
		self.ntss = len(tss)
		self.freq = freq
		self.vmas = []
		self.gran = gran

		# calculate reverse mapping of timesteps for VMAs
		rtss = {ts:i for i,ts in enumerate(tss)}

		# create mappings
		for index, mmap in enumerate(mmaps):
			if mmap == None:
				continue
			self.mmapVMA(mmap[0], mmap[1], mmap[2], tss, rtss, index)
		for umap in munmaps:
			self.unmapVMA(umap[0], umap[1], umap[2])

		# check granularity versus the minimum mmap size
		self.checkGranularity(gran)

		# add pebs records
		self.addPebsRecords(records)

	def mmapVMA(self, start, length, ts, tss, rtss, index):
		vma = VirtualMemoryArea(start, length, ts, tss, rtss, index)
		self.vmas.append(vma)

	def unmapVMA(self, start, length, ts):
		end = start + length
		for vma in self.vmas:
			overlap, exact = vma.inRange(start, end, ts)
			if overlap == None:
				continue
			vma.setUnmap(ts)
			if not exact:
				#TODO
				print("WARNING: split VMA not implemented yet")

	def addPebsRecords(self, records):
		"""Add address records into registered VMAs"""
		GRANULARITY_MASK = ~((0x1<<self.gran)-1)

		# get page of each address
		for i in range(len(records)):
			records[i] = records[i] & GRANULARITY_MASK

		# Add each address in a record to its VMA
		for tsi, record in enumerate(records):
			ts = self.tss[tsi]
			fvmas = self.getVMAinTimeRange(ts)
			for i, addr in enumerate(record):

				if addr < self.minaddr:
					self.minaddr = addr
				elif addr > self.maxaddr:
					self.maxaddr = addr

				for vma in fvmas:
					if vma.tryAdd(ts, addr):
						break

		if vb > 0:
			print("Address Space summary")
			print("=====================")
			print("timesteps:", len(records))
			print("minaddr:", "0x"+tohex(self.minaddr))
			print("maxaddr:", "0x"+tohex(self.maxaddr))
			print("")
			print("Number of Virtual Memory Addresses:", len(self.vmas))
			for i, vma in enumerate(self.vmas):
				print("Virtual Memory Address number",i)
				print(vma, "\n")
			print("=====================")

	def checkGranularity(self, gran):
		"""Check if provided granularity is valid. Calculate the
		biggest possible otherwise"""
		force = False

		if gran != "max":
			pgran = (1<<gran)
			nmvmas = []
			for vma in self.vmas:
				if vma.length % pgran != 0:
					nmvmas.append(vma.index)
					force = True
			if force:
				print("WARNING: granularity is not multiple of VMAs:",
					",".join(map(str,nmvmas)))

		if gran == "max" or force:
			vmaLengths = [0 for x in self.vmas]
			for i, vma in enumerate(self.vmas):
				vmaLengths[i]=vma.length

			maxgran = reduce(gcd, vmaLengths)
			self.gran = int(log(maxgran,2))
			print("Using max common granularity of", maxgran,"(",self.gran,")")

	def getVMAinTimeRange(self, ts):
		vmas = []
		for vma in self.vmas:
			if vma.inTimeRange(ts):
				vmas.append(vma)
		return vmas

	def formatTimeGetFactor(self, scale):
		fact = 0

		if scale == "s":
			fact = 1
		elif scale == "ms":
			fact = 1000
		elif scale == "us":
			fact = 1000000
		elif scale == "ns":
			fact = 1000000000
		else:
			print("scale",scale,"not recognized, exiting")
			sys.exit(1)

		return fact

	def formatTimestamp(self, ts, scale):
		first = self.tss[0]
		hz = self.freq*1000*1000
		fact = self.formatTimeGetFactor(scale)
		return int(((ts-first)/hz)*fact)

	def formatTimeScale(self, scale):
		"""Format from cycles to the desired scale"""
		tss = self.tss
		hz = self.freq*1000*1000
		ftss = [0 for x in range(len(tss))]

		first = tss[0]
		hz = self.freq*1000*1000
		fact = self.formatTimeGetFactor(scale)
		for i,ts in enumerate(tss):
			ftss[i] = int(((ts-first)/hz)*fact)
			if i>0 and ftss[i] == ftss[i-1]:
				print("Warning: time resolution too small")

		return ftss

	def plotHeatTimelinePltNoTime(self, save, extension):
		"""Plot heatmaps in a timeline basis, all in a single image without
		real spacing between timesteps"""

		for vma in self.vmas:
			if vma.isEmpty():
				print("skipping empty VMA",vma.index,":",vma.name())
				continue

			fig, ax = plt.subplots()

			heatmaps = vma.heatmaps

			naddr = vma.getAddressArea(self.gran)
			minaddr = vma.minaddr>>self.gran

			print("showing VMA",vma.index,":       ", vma.name(), "of", naddr, "x", self.ntss)
			timeline = np.zeros((naddr, self.ntss))
			if vb > 1:
				print("Processing", self.ntss, "timesteps for timeline")
			for ts, heatmap in enumerate(heatmaps):
				if vb > 1:
					print(" - processing timestep:",ts)
				for pair in sorted(heatmap.items()):
					addr = (pair[0]>>self.gran)-minaddr
					naccess = pair[1][0]
					timeline[addr][ts] = naccess

			# set hexadecimal values for Y axis
			fmt = self.AddressSpaceFormatter(self.gran, minaddr)
			ax.get_yaxis().set_major_formatter(fmt)

			im = ax.matshow(timeline, cmap=self.cmap,
					vmin=self.minAccess, vmax=self.maxAccess,
					interpolation='None', aspect="auto")
			#im = ax.pcolorfast(timeline, cmap='rainbow',
			#		vmin=self.minAccess, vmax=self.maxAccess)

			# set colorbar
			fig.subplots_adjust(right=0.8)
			cbar_ax = fig.add_axes([0.87, 0.15, 0.05, 0.7])
			cbar_ax.set_title("L2 MISSES")
			fig.colorbar(im, cax=cbar_ax)

			# configure axis
			ax.xaxis.set_ticks_position('bottom')
			ax.set_title("PEBS Memory Access Timeline")
			ax.set_xlabel("Timesteps")
			ax.set_ylabel("Page memory addresses")

			fig.subplots_adjust(left=0.25)

			if (save == None):
				plt.show()
			else:
				fig.savefig(save+"_"+str(vma.index)+"."+extension)

	def plotHeatTimelinePltFull(self, save, extension):
		ftss = self.formatTimeScale(self.timeScale)
		for vma in self.vmas:

			if vma.isEmpty():
				print("skipping empty VMA",vma.index,":",vma.name())
				continue

			fig, ax = plt.subplots()

			heatmaps = vma.heatmaps
			naddr = vma.getAddressArea(self.gran)
			minaddr = vma.minaddr>>self.gran
			print("showing VMA",vma.index,":       ", vma.name(), "of", naddr, "x", self.ntss)
			timeline = np.zeros((naddr, ftss[-1]+1))
			if vb > 1:
				print("Processing", self.ntss, "timesteps for timeline")
			for tsi, heatmap in enumerate(heatmaps):
				ts = ftss[tsi]
				if vb > 1:
					print(" - processing timestep:",tsi,"(",ts,")")
				for pair in sorted(heatmap.items()):
					addr = (pair[0]>>self.gran)-minaddr
					naccess = pair[1][0]
					timeline[addr][ts] = naccess

			# set hexadecimal values for Y axis
			fmt = self.AddressSpaceFormatter(self.gran, minaddr)
			ax.get_yaxis().set_major_formatter(fmt)

			im = ax.matshow(timeline, cmap=self.cmap,
					vmin=self.minAccess, vmax=self.maxAccess,
					interpolation='None', aspect="auto")

			# set colorbar
			fig.subplots_adjust(right=0.8)
			cbar_ax = fig.add_axes([0.85, 0.15, 0.05, 0.7])
			fig.colorbar(im, cax=cbar_ax)

			# configure axis
			ax.xaxis.set_ticks_position('bottom')
			ax.set_title("PEBS Memory Access Timeline")
			ax.set_xlabel("Timesteps")
			ax.set_ylabel("Page memory addresses")
			fig.subplots_adjust(left=0.25)

			if (save == None):
				plt.show()
			else:
				fig.savefig(save+"_"+str(vma.index)+"."+extension)

	#def plot_coo_matrix(self, m):
	#	if not isinstance(m, coo_matrix):
	#		m = coo_matrix(m)
	#	fig = plt.figure()
	#	ax = fig.add_subplot(111, facecolor='black')
	#	ax.plot(m.col, m.row, 's', color='white', ms=1)
	#	ax.set_xlim(0, m.shape[1])
	#	ax.set_ylim(0, m.shape[0])
	#	ax.set_aspect('equal')
	#	for spine in ax.spines.values():
	#		spine.set_visible(False)
	#	ax.invert_yaxis()
	#	ax.set_aspect('equal')
	#	ax.set_xticks([])
	#	ax.set_yticks([])
	#	return ax

	#def plotHeatTimelinePltSparse(self):
	#	ftss = self.formatTimeScale(self.timeScale)
	#	for vma in self.vmas:

	#		if vma.isEmpty():
	#			print("skipping empty vma:",vma.name())
	#			continue

	#		fig, ax = plt.subplots()

	#		cols = []
	#		rows = []
	#		vals = []

	#		heatmaps = vma.heatmaps
	#		naddr = vma.getAddressBoundaries(self.gran)
	#		minpage = vma.minaddr>>12

	#		if vb > 1:
	#			print("Processing", self.ntss, "timesteps for timeline")
	#		for tsi, heatmap in enumerate(heatmaps):
	#			ts = ftss[tsi]
	#			if vb > 1:
	#				print(" - processing timestep:",tsi,"(",ts,")")
	#			for pair in sorted(heatmap.items()):
	#				addr = (pair[0]>>12)-minpage
	#				naccess = pair[1][0]
	#				cols.append(addr)
	#				rows.append(ts)
	#				vals.append(naccess)

	#		m = coo_matrix((vals, (rows,cols)), shape=(ftss[-1]+1, npages))
	#		ax = self.plot_coo_matrix(m)
	#		plt.show()

	#		continue

	#		# set hexadecimal values for Y axis
	#		fmt = self.AddressSpaceFormatter(minpage)
	#		ax.get_yaxis().set_major_formatter(fmt)

	#		im = ax.matshow(timeline, cmap='rainbow',
	#				vmin=self.minAccess, vmax=self.maxAccess,
	#				interpolation='None', aspect="auto")
	#		#im = ax.pcolormesh(timeline,vmin=self.minAccess, vmax=self.maxAccess)

	#		# set colorbar
	#		fig.subplots_adjust(right=0.8)
	#		cbar_ax = fig.add_axes([0.85, 0.15, 0.05, 0.7])
	#		fig.colorbar(im, cax=cbar_ax)

	#		# configure axis
	#		ax.xaxis.set_ticks_position('bottom')
	#		ax.set_title("PEBS Memory Access Timeline")
	#		ax.set_xlabel("Timesteps")
	#		ax.set_ylabel("Page memory addresses")

	#		fig.subplots_adjust(left=0.25)
	#		plt.show()
	#		#fig.savefig('plot')

	def plot(self, plotType, save, extension):
		if self.vmas==None:
			print("No vmas in address space, exiting")
			sys.exit()

		self.minAccess, self.maxAccess = self.vmas[0].getAccessRange(self.gran)
		for vma in self.vmas[1:]:
			minAccess, maxAccess = vma.getAccessRange(self.gran)
			if minAccess < self.minAccess:
				self.minAccess = minAccess
			if maxAccess > self.maxAccess:
				self.maxAccess = maxAccess

		if plotType == "plt-compact":
			# plot without timestamp notion
			self.plotHeatTimelinePltNoTime(save, extension)
		elif plotType == "plt-full":
			# plot matrix-based with timestamp notion
			self.plotHeatTimelinePltFull(save, extension)
	#	elif plotType == "plt-sparse":
	#		# plot matrix-based with timestamp notion
	#		self.plotHeatTimelinePltSparse()


class VirtualMemoryArea:
	index = 0
	ntss = 0
	tss = None
	rtss = None
	heatmaps = None

	size = [1, 1]
	boundBox = None

	startAddress = -1
	endAddress   = -1
	length       =  0
	startTs      = -1
	endTs        = -1

	ndiff        = 0
	ntotal       = 0

	minaddr = 0xffffffffffffffff
	maxaddr = 0x0

	def __init__(self, startAddress, length, startTs, tss, rtss, index):
		self.startAddress = startAddress
		self.length = length
		self.endAddress = startAddress + length
		self.startTs = startTs
		self.boundBox = BoundingBox()
		self.heatmaps = [{} for x in range(len(tss))]
		self.ntss = len(tss)
		self.tss = tss
		self.rtss = rtss
		self.index = index

	def isEmpty(self):
		return self.ntotal == 0

	def getAddressArea(self, gran=0):
		return self.boundBox.area(gran)

	def inTimeRange(self, ts):
		return (ts >= self.startTs and (self.endTs == -1 or ts < self.endTs))

	def inAddressRange(self, addr):
		return (self.startAddress <= addr)  and (addr < self.endAddress)

	def checkAddressOverlap(self, startAddress, endAddress):
		if (self.startAddress <= startAddress) and (startAddress < self.endAddress):
			start = startAddress
			exact = (self.startAddress == startAddress) and (self.endAddress == endAddress)
			if (endAddress < self.endAddress):
				end = endAddress
			else:
				end = self.endAddress
			return [start, end], exact
		else:
			return None, 0

	def inRange(self, startAddress, endAddress, ts):
		if not self.inTimeRange(ts):
			return None, 0

		return self.checkAddressOverlap(startAddress, endAddress)

	def setUnmap(self, endTs):
		self.endTs = endTs

	def tryAdd(self, ts, addr):
		"""Add address into VMA if in range. Returns 1 if success, 0 otherwise"""
		if not self.inTimeRange(ts):
			return 0
		if not self.inAddressRange(addr):
			return 0

		tsi = self.rtss[ts]
		if self.heatmaps[tsi].get(addr) == None:
			heat = 0
			count = 1
			svg_x = addr%self.size[0]
			svg_y = addr//self.size[0]
			point = [svg_x, svg_y]

			self.heatmaps[tsi][addr] = [count, point, heat]
			self.boundBox.update(point)

			if addr < self.minaddr:
				self.minaddr = addr
			elif addr > self.maxaddr:
				self.maxaddr = addr

			self.ndiff+=1
		else:
			self.heatmaps[tsi][addr][0] += 1

		self.ntotal+=1

		return 1

	def getAccessRange(self, gran=0):
		"""Calculate minimum and maximum Access boundaries """
		nonEmptyHeatmaps = [x for x in self.heatmaps if len(x) > 0]
		if (len(nonEmptyHeatmaps) == 0):
			return 0, 0

		minAccess = list(nonEmptyHeatmaps[0].values())[0][0]
		maxAccess = 0
		naddr = self.getAddressArea(gran)

		for heatmap in nonEmptyHeatmaps:
			for k, v in heatmap.items():
				if v[0] > maxAccess:
					maxAccess = v[0]
				elif v[0] < minAccess:
					minAccess = v[0]
			if len(heatmap) != naddr:
				minAccess = 0

		return minAccess, maxAccess

	def name(self):
		return "0x"+str(tohex(self.startAddress))+"-0x"+str(tohex(self.endAddress))

	def __str__(self):
		ret =  \
		"ntss "              + str(self.ntss)                + "\n" + \
		"startAddress 0x"    + str(tohex(self.startAddress)) + "\n" + \
		"endAddress 0x"      + str(tohex(self.endAddress))   + "\n" + \
		"length "            + str(self.length)              + "\n" + \
		"startTs "           + str(self.startTs)             + "\n" + \
		"endTs "             + str(self.endTs)               + "\n" + \
		"found minaddr 0x"   + str(tohex(self.minaddr))      + "\n" + \
		"found maxaddr 0x"   + str(tohex(self.maxaddr))      + "\n" + \
		"total records:"     + str(self.ntotal)              + "\n" + \
		"different records:" + str(self.ndiff)               + "\n" + \
		"boundbox "          + str(self.boundBox)            + "\n" + \
		"size "              + str(self.size)#                + "\n" + \
		#"heatmaps "        + str(self.heatmaps)

		return ret

class BoundingBox:
	maxi = 0x0
	mini = 0xffffffffffffffff
	boundBox =  None
	empty = True

	def __init__(self):
		self.boundBox = [self.mini, self.mini, self.maxi, self.maxi]

	def update(self, point):
		""" Update bounding box with new point"""
		if point[0] < self.boundBox[0]:
			self.boundBox[0] = point[0]
		if point[0] > self.boundBox[2]:
			self.boundBox[2] = point[0]

		if point[1] < self.boundBox[1]:
			self.boundBox[1] = point[1]
		if point[1] > self.boundBox[3]:
			self.boundBox[3] = point[1]

		self.empty = False

	def isEmpty(self):
		return self.empty

	def area(self, gran=0):
		if self.empty:
			return 0
		pr = [x>>gran for x in self.boundBox]
		return (pr[2] - pr[0]+1)*(pr[3]-pr[1]+1)

	def __str__(self):
		ret = \
			"boundbox:   "  + str(self.boundBox)                   + "\n" + \
			"  - empty:"  + str(self.empty)                        + "\n" + \
			"  - xmax: "  + str(self.boundBox[2]-self.boundBox[0]) + "\n" + \
			"  - ymax: "  + str(self.boundBox[3]-self.boundBox[1]) + "\n" + \
			"  - page Area:  " + str(self.area(12))
		return ret

def argparse_check_power_of_two(val):
	ival = int(val)
	if (ival & (ival-1)) == 0:
		return int(log(ival,2))
	else:
		raise argparse.ArgumentTypeError("%s is not a power of two" % val)

def argparse_check_granularity(val):
	if (val == "byte") or (val == "B"):
		return 1
	elif val == "page":
		return 12
	elif (val == "KiB") or (val == "K"):
		return 10
	elif (val == "MiB") or (val == "M"):
		return 20
	elif (val == "GiB") or (val == "G"):
		return 30
	elif (val == "max"):
		return "max"
	else:
		return argparse_check_power_of_two(val)

def check_hex_address(val):
	try:
		return int(val,16)
	except:
		raise argparse.ArgumentTypeError("%s address format not understood" % val)

def parse_arguments():
	"""Parse script arguments"""
	global vb

	parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
	#parser = argparse.ArgumentParser()

	parser.add_argument('file', action='store', default="pebs.out",
			help="PEBS dump file to analyze. Default is pebs.out")
	parser.add_argument('-x', '--size', action='store', dest='size',
			help="""Size of the memory region: D1xD2 e.g. 10x20.
			This determines the layout of the memory area
			displayed.""")
	parser.add_argument('-m', '--vmas', action='store', dest='vmas',
			help="""Comma separated values of VMAs IDs to work with""")
	parser.add_argument('-g', '--granularity', action='store', default=12,
			type=argparse_check_granularity, dest='granularity',
			help="""Granularity of displayed blocks of memory. By
			default is page size. Accepts numeric granularity
			(which must be a multiple of two) or a predefined one
			from "byte/page/KiB/MiB/GiB" or "B/K/M/G". Default is
			page.""")
	parser.add_argument('-s', '--save', action='store',
			help="""specify the name of the file to store the plots""")
	parser.add_argument('-f', '--format', action='store', default="pdf",
			help="""specify the format to store the plots file.
			Only useful if used with --save. Supports all formats
			matplotlib supports, just write the format suffix such
			as png or svg. Default is pdf.""")
	#parser.add_argument('-f', '--first-address', action='store',
	#		type=check_hex_address, dest='firstAddress', default=0,
	#		help="""First virtual address of the buffer in hex. The
	#		first address is needed when the user memory segment is
	#		not aligned to the buffer column size (in C ordering).
	#		This is only useful when used in combination with
	#		--size.""")
	parser.add_argument('-v', '--verbose', action='count', default=0,
			help="Increase output verbosity")
	#parser.add_argument('-a', '--accumulate', action='store_true',
	#		help="""Each timestamp svg will show the data accesses
	#		of the previous timestamps.""")
	parser.add_argument('-a', '--address-histogram', action='store_true',
			dest="addressHistogram",
			help="""Plot memory address histograms. Useful to
			detect outlayers""")
	parser.add_argument('-i', '--interrupt-histogram', action='store_true',
			dest="interruptHistogram",
			help="""Plot pebs interrupt interval histogram.""")
	parser.add_argument('-t', '--timeline', action='store', default="none",
			choices=["plt-compact", "plt-full", "plt-sparse",
			"plt-rect", "sw-rect", "seaborn", "none"],
			help="""Plot memory address timeline. This ignores the
			--size layout and --granularity. Multiple renderers are
			provided:\n
			 - plt-compact: matplotlib without real time spacing\n
			 - plt-full: matplotlib with real time spacing (huge memory consumption)\n
			 - plt-sparse: matplotlib sparse matrix\n
			 - sw-rect: swgwrite plot rectangle by rectangle\n
			 - plt-rect: matplotlib plot rectangle by rectangle\n
			 - seaborn: use seaborn lib with real time spacing (huge memory consumption)\n
			 - none: no timeline (default)""")
	#parser.add_argument('-o', '--outlier', action='store', type=int,
	#		default=2, help="""Set outlier filtering parameter.
	#		Default is 2. Set to 0 to skip outlier filtering
	#		phase""")

	args = parser.parse_args()

	if args.size != None:
		args.size = [int(x) for x in args.size.split("x")]

	if args.vmas:
		args.vmas = map(int,args.vmas.split(","))

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

def readPebsDump(filename):
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

def reject_outliers(data, m = 2.):
	"""Remove outlier in the provided data set based on the m argument"""
	m = float(m)
	d = np.abs(data - np.median(data))
	mdev = np.median(d)
	s = d/mdev if mdev else 0.
	return data[s<m]

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
	"""Calculate minimum and maximum heat boundaries """
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

def plotAddressHistogram(records, save, extension):
	"""Plot histograms of memory accesses on files"""
	if vb > 0:
		print("Plotting", len(records), "histograms")
	for ts, record in enumerate(records):
		if vb > 0:
			print(" - plotting histogram",ts)
		plt.hist(record, bins=30)
		plt.ylabel('Memory addresses')
		plt.show()
		if save == None:
			plt.show()
		else:
			plt.savefig(save+"_"+str(ts)+"."+extension)
		plt.clf()

def plotInterruptHistogram(addressSpace, save, extension):
	"""Plot histograms of pebs interrupt interval"""

	ftss = addressSpace.formatTimeScale(AddressSpace.timeScale)

	if len(ftss) < 3:
		print("Not enough data to create Interrupt Histogram. Only",len(ftss),"samples found.")
		return

	dtss = [0 for x in range(len(ftss)-2)]

	for i in range(len(ftss)-2):
		dtss[i] = ftss[i+1]-ftss[i]

	plt.hist(dtss, bins=30)
	plt.title('PEBS Interrupts Interval')
	plt.xlabel('Time Interval in ' + AddressSpace.timeScale)
	plt.ylabel('Count')

	if save == None:
		plt.show()
	else:
		plt.savefig(save+"."+extension)

	plt.clf()


def plotHeatTimelineSeaborn(tss, heatmaps, boundbox, minaddr):
	"""Plot heatmaps in a timeline basis, using seaborn package"""
	naddr = (boundbox[3]-boundbox[1]+1)
	maxts = tss[-1] + 1
	if vb > 1:
		print("Allocating numpy array of", naddr, "x", maxts,"=",naddr*maxts)
	timeline = np.zeros((naddr, maxts))
	if vb > 1:
		print("Processing",len(heatmaps),"timesteps for timeline")
	for tsi, heatmap in enumerate(heatmaps):
		if vb > 1:
			print(" - processing timestep:",tsi)
		ts = tss[tsi]
		for pair in sorted(heatmap.items()):
			addr = pair[0]-minaddr
			naccess = pair[1][0]
			timeline[addr][ts] = naccess
	print("creating heatmap...")
	ax = sns.heatmap(timeline)
	print("showing heatmap...")
	plt.show()

def to_hex(x, pos):
	    return '%x' % int(x)

def plotHeatTimelinePltRect(heatmaps, boundbox, tss):
	"""Plot timeline rectangle by rectangle using matplotlib"""
	ax = plt.subplot(111)
	# Set x and y ranges for axis
	plt.xlim(tss[0], tss[-1])
	plt.ylim(boundbox[1],boundbox[3])

	# Set hexadecimal values for Y axis
	fmt = ticker.FuncFormatter(to_hex)
	ax.get_yaxis().set_major_formatter(fmt)

	patchesList = []
	if vb > 1:
		print("Drawing", len(heatmaps), "timesteps")
	for ts, heatmap in enumerate(heatmaps):
		if vb > 1:
			print(" - drawing timestep", ts)

		x0 = int(tss[ts])
		for k, v in heatmap.items():
			y0 = int(k)
			col = v[2]
			#rgb = rgb(v[2], 0, 0)
			if vb == 3:
				print("Insert access (",x0,",",y0,") accesses:",
				      v[0], "color:",v[2])
			r = patches.Rectangle((x0,y0),1,1,
					      linewidth=1,
					      edgecolor='r',
					      facecolor='r')
			patchesList.append(r)

	p = PatchCollection(patchesList)
	ax.add_collection(p)
	#plt.savefig("pebs.svg")
	plt.show()

def plotHeatTimelineSwRect(heatmaps, boundbox, tss):
	"""Plot timeline rectangle by rectangle using svgwrite"""
	def group(classname):
		return dwg.add(dwg.g(class_=classname))

	x0   = int(tss[0])
	y0   = int(boundbox[1])
	xlen = int(tss[-1] - tss[0])
	ylen = int(boundbox[3] - boundbox[1]) + 1

	dwg = svgwrite.Drawing('pebs_timeline.svg', size=SVG_SIZE)
	dwg.viewbox(x0, y0, xlen, ylen)
	dwg.defs.add(dwg.style(CSS_STYLES))

	# set background
	dwg.add(dwg.rect(insert=(x0, y0), size=(xlen, ylen), class_='background'))

	mem = group("mem")

	print("Drawing", len(heatmaps), "timesteps")
	for ts, heatmap in enumerate(heatmaps):
		print(" - drawing timestep", ts)

		x0 = int(tss[ts])
		for k, v in heatmap.items():
			y0 = int(k)
			col = v[2]
			if vb == 3:
				print("Insert access (",x0,",",y0,") accesses:", v[0], "color:",v[2])
			access = dwg.rect(insert=(x0, y0), size=(1, 1))
			mem.add(access)
			u = dwg.use(access, fill=rgb(col, 0, 0))
			dwg.add(u)

	dwg.save()

def filterVMAs(mmaps, vmas):
	if vmas == None:
		return mmaps

	fmmaps = [None for x in mmaps]

	for vmaid in vmas:
		fmmaps[vmaid] = mmaps[vmaid]

	return fmmaps

# balazs TODO
#  - option to store in pdf format

if __name__ == '__main__':
	xeon_phi_7210_freq = 1300

	args = parse_arguments()

	tss, mmaps, munmaps, records = readPebsDump(args.file)

	fmmaps = filterVMAs(mmaps, args.vmas)

	addressSpace = AddressSpace(tss, fmmaps, munmaps, records,
				    xeon_phi_7210_freq, args.granularity)

	if args.timeline:
		addressSpace.plot(args.timeline, args.save, args.format)

	if args.addressHistogram:
		plotAddressHistogram(records, args.save, args.format)

	if args.interruptHistogram:
		plotInterruptHistogram(addressSpace, args.save, args.format)


	#heatmaps, boundbox, minaddr = formatPebsData(records, args.firstAddress,
	#				    args.granularity, args.size, args.outlier)

	#if args.histograms:
	#	plotHistograms(records)

	#if args.accumulate:
	#	minheat, maxheat = accumulateAddresses(heatmaps)
	#else:
	#	minheat, maxheat = calcHeatBoundaries(heatmaps)
	#if vb > 0:
	#	print("min/maxheat:",minheat,",",maxheat)

	#xeon_phi_7210_freq = 1300
	#formatTimeScale(tss, xeon_phi_7210_freq, "ms")

	#if args.timeline == "plt-full":
	#	# plot matrix-based with timestamp notion
	#	plotHeatTimelinePltFull(tss, heatmaps, boundbox, minaddr)
	#elif args.timeline == "plt-compact":
	#	# plot without timestamp notion
	#	plotHeatTimelinePltNoTime(heatmaps, boundbox, minaddr)
	#elif args.timeline == "plt-rect":
	#	# plot rectangle by rectangle
	#	calcHeatColor(heatmaps, minheat, maxheat)
	#	plotHeatTimelinePltRect(heatmaps, boundbox, tss)
	#elif args.timeline == "sw-rect":
	#	#plot using svgwrite
	#	calcHeatColor(heatmaps, minheat, maxheat)
	#	plotHeatTimelineSwRect(heatmaps, boundbox, tss)
	#elif args.timeline == "seaborn":
	#	plotHeatTimelineSeaborn(tss, heatmaps, boundbox, minaddr)
	#elif args.timeline == "none":
	#	#No timeline
	#	calcHeatColor(heatmaps, minheat, maxheat)
	#	plotHeatMapsPar('pebs', heatmaps, boundbox)


#lx=[]
#ly=[]
#for k, v in heatmaps[0].items():
#	x0 = int(v[1][0])
#	y0 = int(v[1][1])
#	lx.append(x0)
#	ly.append(y0)
#lsx = sorted(lx)
#lsy = sorted(ly)
#for e in lsx:
#	print(e - lsx[0])
#for e in lsy:
#	print(e)

#plt.show()
