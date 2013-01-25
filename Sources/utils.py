# -----------------------------------------------------------------------------
#
# SYSTEM
#
# -----------------------------------------------------------------------------

class System:
	"""A collection of utilities to interact with system information"""

	LAST_CPU_STAT = None

	@classmethod
	def MemoryInfo(cls):
		"""Returns the content of /proc/meminfo as a dictionary 'key' -> 'value'
		where value is in kB"""
		res = {}
		for line in cat("/proc/meminfo").split("\n")[:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			name, value = line[:2]
			res[name.replace("(", "_").replace(")", "_").replace(":", "")] = int(value)
		return res

	@classmethod
	def MemoryUsage(cls):
		"""Returns the memory usage (between 0.0 and 1.0) on this system, which
		is total memory - free memory - cached memory."""
		meminfo = cls.MemoryInfo()
		return (meminfo["MemTotal"] - meminfo["MemFree"] - meminfo["Cached"]) / float(meminfo["MemTotal"])

	@classmethod
	def DiskUsage(cls):
		"""Returns a dictionary 'device' -> 'percentage' representing the
		usage of each device. A percentage of 1.0 means completely used,
		0.0 means unused."""
		# >> df -iP
		# Sys. de fich.            Inodes   IUtil.  ILib. IUti% Monte sur
		# /dev/sda1             915712  241790  673922   27% /
		# none                  210977     788  210189    1% /dev
		# none                  215028      19  215009    1% /dev/shm
		# none                  215028      71  214957    1% /var/run
		# none                  215028       2  215026    1% /var/lock
		# /dev/sda5            8364032  500833 7863199    6% /home
		# /home/sebastien/.Private 8364032  500833 7863199    6% /home/sebastien
		res = {}
		for line in popen("df -kP").split("\n")[1:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			system, inodes, used_inodes, free_inodes, usage, mount = line
			try:
				usage = float(usage[:-1])
			except ValueError:
				usage = 0
			res[mount] = float(usage) / 100.0
		return res

	@classmethod
	def CPUStats(cls):
		"""Returns  CPU stats, that can be used to get the CPUUsage"""
		# From <http://ubuntuforums.org/showthread.php?t=148781>
		time_list = cat("/proc/stat").split("\n")[0].split(" ")[2:6]
		res = map(int, time_list)
		cls.LAST_CPU_STAT = res
		return res

	@classmethod
	def CPUUsage(cls, cpuStat=None):
		if not cpuStat:
			cpuStat = cls.LAST_CPU_STAT
		stat_now = cls.CPUStats()
		res = []
		for i in range(len(cpuStat)):
			res.append(stat_now[i] - cpuStat[i])
		try:
			usage = (100 - (res[len(res) - 1] * 100.00 / sum(res))) / 100.0
		except ZeroDivisionError:
			usage = 0
		return usage

	@classmethod
	def GetInterfaceStats(cls):
		# $/proc/net$ sudo cat dev
		# Inter-|   Receive                                                |  Transmit
		#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
		#     lo:454586083  954504    0    0    0     0          0         0 454586083  954504    0    0    0     0       0          0
		#   eth0:55735297   85080    0    0    0     0          0         0  5428643   67978    0    0    0     0       0          0
		#   eth1:3300079052153 11645531967    0 8098    0     0          0         0 3409466791555 6131411252    0    0    0     0       0          0
		#  edge0:       0       0    0    0    0     0          0         0     9763      87    0    0    0     0       0          0
		res = {}
		for line in cat("/proc/net/dev").split("\n")[2:-1]:
			interface, stats = RE_SPACES.sub(" ", line).strip().split(":", 1)
			stats = map(long, stats.strip().split(" "))
			rx_bytes, rx_pack, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compr, rx_multicast, \
			tx_bytes, tx_pack, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed = stats
			res[interface] = {
				"rx": dict(
					bytes=rx_bytes,
					packets=rx_pack,
					errors=rx_errs,
					drop=rx_drop
				),
				"tx": dict(
					bytes=tx_bytes,
					packets=tx_pack,
					errors=tx_errs,
					drop=tx_drop
				),
				"total": dict(
					bytes=tx_bytes + rx_bytes,
					packets=tx_pack + rx_pack,
					errors=tx_errs + rx_errs,
					drop=tx_drop + rx_drop
				)
			}
		return res
