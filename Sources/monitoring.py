#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Monitoring
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   10-Feb-2010
# Last mod.         :   22-Nov-2012
# -----------------------------------------------------------------------------

import re, sys, os, time, datetime, stat, smtplib, string, json, fnmatch
import httplib, socket, threading, subprocess, glob, traceback


from actions import *
from rules import *

# TODO: Add System health metrics (CPU%, MEM%, DISK%, I/O, INODES)

# FIXME: HTTP should use httplib2, pool HTTP requests (and limit to a maximum),
# should also force close after a certain time (cappedpool)

# FIXME: Prevent flooding of taskrunner, ie. when tasks take longer than
# their duration, this is valid for actions or rules taking too long.

# FIXME: One of the scenario is that the frequency of an action is shorter than
# the execution time, so that you have an accumulation

# FIXME: Ensure re-ordering of logging

#  File "sample-reporter.py", line 35, in <module>
#    fail    = [SendStat(ADKIT_STATSERVICE, "mediaserver.ms-1.failure")]
#  File "/home/sebastien/Projects/Local/lib/python/monitoring.py", line 669, in run
#    Runner(rule,context=service,iteration=self.iteration).onRunEnded(self.onRuleEnded).run()
#  File "/home/sebastien/Projects/Local/lib/python/monitoring.py", line 620, in run
#    self._thread.start()
#  File "/usr/lib/python2.6/threading.py", line 474, in start
#    _start_new_thread(self.__bootstrap, ())
#thread.error: can't start new thread

__version__ = "0.9.5"

RE_SPACES  = re.compile("\s+")
RE_INTEGER = re.compile("\d+")

def config(variable, default, normalize=lambda _:_):
	return normalize(os.environ.get(variable.upper().replace(".","_")) or default)

def cat(path):
	"""Outputs the content of the file at the given path"""
	try:
		with file(path, 'r') as f:
			d = f.read()
	except Exception,e:
		d = None
	return d

def count(path):
	"""Count the number of files and directories at the given path"""
	try:
		return len(os.listdir(path))
	except Exception,e:
		# We most probably hit a permission denied here
		return -1

def now():
	"""Returns the current time in milliseconds"""
	return time.time() * 1000

def spawn(cmd, cwd=None):
	"""Spawn a completely detached subprocess (i.e., a daemon).
	"""
	# FROM: http://stackoverflow.com/questions/972362/spawning-process-from-python
	# fork the first time (to make a non-session-leader child process)
	try:
		pid = os.fork()
	except OSError, e:
		raise RuntimeError("1st fork failed: %s [%d]" % (e.strerror, e.errno))
	if pid != 0:
		# parent (calling) process is all done
		return pid
	# detach from controlling terminal (to make child a session-leader)
	os.setsid()
	try:
		pid = os.fork()
	except OSError, e:
		raise RuntimeError("2nd fork failed: %s [%d]" % (e.strerror, e.errno))
		raise Exception, "%s [%d]" % (e.strerror, e.errno)
	if pid != 0:
		# child process is all done
		os._exit(0)
	# grandchild process now non-session-leader, detached from parent
	# grandchild process must now close all open files
	try:
		maxfd = os.sysconf("SC_OPEN_MAX")
	except (AttributeError, ValueError):
		maxfd = 1024
	for fd in range(maxfd):
		try:
			os.close(fd)
		except OSError: # ERROR, fd wasn't open to begin with (ignored)
			pass
	# redirect stdin, stdout and stderr to /dev/null
	if (hasattr(os, "devnull")):
		REDIRECT_TO = os.devnull
	else:
		REDIRECT_TO = "/dev/null"
	os.open(REDIRECT_TO, os.O_RDWR) # standard input (0)
	os.dup2(0, 1)
	os.dup2(0, 2)
	# and finally let's execute the executable for the daemon!
	try:
		args = filter(lambda _:_, map(lambda _:_.strip(), cmd.split(" ")))
		path_to_executable = args[0]
		args = args[1:]
		os.execv(path_to_executable, args)
	except Exception, e:
		# oops, we're cut off from the world, let's just give up
		os._exit(255)

def popen(command, cwd=None, check=False, detach=False):
	"""Returns the stdout from the given command, using the subproces
	command."""
	if detach:
		return spawn(command, cwd)
	else:
		cmd      = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
		status   = cmd.wait()
		res, err = cmd.communicate()
		if status == 0:
			return res
		else:
			return (status, err)

def timestamp():
	"""Returns the current timestamp as an ISO-8601 time
	("1977-04-22T01:00:00-05:00")"""
	n = datetime.datetime.now()
	return "%04d-%02d-%02dT%02d:%02d:%02d" % (
		n.year, n.month, n.day, n.hour, n.minute, n.second
	)


# -----------------------------------------------------------------------------
#
# SIGNAL HANDLING
#
# -----------------------------------------------------------------------------

class Signals:
	"""Takes care of registering/unregistering signals so that shutdown
	(on Ctrl-C) works properly."""

	SINGLETON = None

	@classmethod
	def Setup(cls):
		"""Sets up the shutdown signal handlers."""
		if cls.SINGLETON is None:
			cls.SINGLETON = Signals()
		cls.SINGLETON.setup()

	@classmethod
	def OnShutdown(cls, callback):
		"""Registers a new callback to be triggered on
		SIGINT/SIGHUP/SIGABRT/SIQUITE/SIGTERM."""
		if cls.SINGLETON is None:
			cls.SINGLETON = Signals()
		assert not cls.SINGLETON.signalsRegistered, "OnShutdown must be called before Setup."
		cls.SINGLETON.onShutdown.append(callback)

	def __init__(self):
		self.signalsRegistered = []
		self.onShutdown = []
		try:
			import signal
			self.hasSignalModule = True
		except:
			self.hasSignalModule = False

	def setup(self):
		"""Sets up the signals, registering the shutdown function. You only
		need to call this function once."""
		if self.hasSignalModule and not self.signalsRegistered:
			# Jython does not support all signals, so we only use
			# the available ones
			signals = ['SIGINT',  'SIGHUP', 'SIGABRT', 'SIGQUIT', 'SIGTERM']
			import signal
			for sig in signals:
				try:
					signal.signal(getattr(signal, sig), self._shutdown)
					self.signalsRegistered.append(sig)
				except Exception, e:
					Logger.Err("[!] monitoring.Signals._registerSignals:%s %s\n" % (sig, e))

	def _shutdown(self, *args):
		"""Safely executes the callbacks registered in self.onShutdown."""
		for callback in self.onShutdown:
			try:
				callback()
			except:
				pass
		sys.exit()


# -----------------------------------------------------------------------------
#
# LOGGER
#
# -----------------------------------------------------------------------------
class Logger:

	SINGLETON = None

	@classmethod
	def I(cls):
		if cls.SINGLETON is None:
			cls.SINGLETON = Logger()
		return cls.SINGLETON

	@classmethod
	def Err(cls, *message):
		cls.I().err(*message)

	@classmethod
	def Warn(cls, *message):
		cls.I().warn(*message)

	@classmethod
	def Info(cls, *message):
		cls.I().info(*message)

	@classmethod
	def Debug(cls, *message):
		cls.I().debug(*message)

	@classmethod
	def Sep(cls):
		cls.I().sep()

	@classmethod
	def Traceback(cls):
		cls.I().traceback()

	@classmethod
	def Output(cls, *message):
		cls.I().output(*message)

	def __init__(self, stream=sys.stdout, prefix=""):
		self.stream = stream
		self.lock = threading.RLock()
		self.prefix = prefix

	def err(self, *message):
		self("[!]", *message)

	def warn(self, *message):
		self("[-]", *message)

	def info(self, *message):
		self("---", *message)

	def debug(self, *message):
		self("   ", *message)

	def traceback( self ):
		exception = traceback.format_exc()
		lines     = exception.split("\n")[:-1]
		for i in range(len(lines)):
			if i == len(lines) - 1:
				self.err(lines[i])
			else:
				self.debug(lines[i])

	def output(self, *message):
		return
		res = []
		for line in message:
			for subline in message.split("\n"):
				res.append(">>> " + subline + "\n")
		self.lock.acquire()
		for line in res:
			self.stream.write(line)
		self.stream.flush()
		self.lock.release()

	def sep(self):
		self.lock.acquire()
		self.stream.write("\n")
		self.stream.flush()
		self.lock.release()

	def __call__(self, prefix, *message):
		self.lock.acquire()
		message = " ".join(map(str, message))
		self.stream.write("%s %s%s %s\n" % (
			timestamp(), self.prefix, prefix, message
		))
		self.stream.flush()
		self.lock.release()


# -----------------------------------------------------------------------------
#
# PROCESS INFORMATION
#
# -----------------------------------------------------------------------------
class Process:
	"""A collection of utilities to manipulate and interact with running
	processes."""
	# See <http://linux.die.net/man/5/proc>

	RE_PS_OUTPUT = re.compile("^%s$" % ("\s+".join([
		"[^.]+",  "(\d+)", "(\d+)", "\d+", "\d+", "\d+", "\d+", "[^ ]+", "[^ ]+", "\d\d\:\d\d\:\d\d", "(.+)"
	])))

	@classmethod
	def Find(cls, command, compare=(lambda a, b: a == b)):
		# FIXME: Probably better to direcly use List()
		# The output looks like this
		# 1000      2446     1 12 84048 82572   0 14:02 ?        00:04:08 python /usr/lib/exaile/exaile.py --datadir=/usr/share/exaile/data --startgui
		# 1000      2472     1  0  2651  3496   0 14:02 ?        00:00:00 /usr/lib/gvfs/gvfsd-http --spawner :1.6 /org/gtk/gvfs/exec_spaw/2
		# 107       2473     1  0  4274  4740   0 14:02 ?        00:00:00 /usr/sbin/hald
		# root      2474  2473  0   883  1292   1 14:02 ?        00:00:00 hald-runner
		# root      2503  2474  0   902  1264   1 14:02 ?        00:00:00 hald-addon-input: Listening on /dev/input/event10 /dev/input/event4 /dev/input/event11 /dev/input/event9 /dev/in
		# root      2508  2474  0   902  1228   0 14:02 ?        00:00:00 /usr/lib/hal/hald-addon-rfkill-killswitch
		# root      2516  2474  0   902  1232   1 14:02 ?        00:00:00 /usr/lib/hal/hald-addon-leds
		# 1000     29393     1  0  6307 17108   1 Feb26 ?        00:00:25 /usr/bin/python /usr/lib/telepathy/telepathy-butterfly'
		# Note: we skip the header and the trailing EOL
		for line in popen("ps -AF").split("\n")[1:-1]:
			match = cls.RE_PS_OUTPUT.match(line)
			if match:
				pid = match.group(1)
				ppid = match.group(2)
				cmd = match.group(3)
				if compare(command, cmd):
					return (pid, ppid, cmd)
			else:
				Logger.Err("Problem with PS output !: " + repr(line))
		return None

	@classmethod
	def List(cls):
		"""Returns a map of pid to cmdline"""
		res = {}
		for p in glob.glob("/proc/*/cmdline"):
			process = p.split("/")[2]
			if process != "self":
				res[int(process)] = cat(p).replace("\x00", " ")
		return res

	@classmethod
	def GetWith(cls, expression, compare=(lambda a, b: fnmatch.fnmatch(a, b))):
		"""Returns a list of all processes that contain the expression
		in their command line."""
		res = []
		expression = "*" + expression + "*"
		for pid, cmdline in cls.List().items():
			if compare(cmdline, expression):
				res.append(pid)
		return res

	@classmethod
	def Status(cls, pid):
		res = {}
		pid = int(pid)
		for line in cat("/proc/%d/status" % (pid)).split("\n"):
			if not line:
				continue
			name, value = line.split(":", 1)
			res[name.lower()] = value.strip()
		return res

	@classmethod
	def Start(cls, command, cwd=None):
		# FIXME: Not sure if we need something like & at the end
		command += ""
		Logger.Info("Starting process: " + repr(command))
		popen(command, cwd)

	@classmethod
	def Kill(cls, pid):
		Logger.Info("Killing process: " + repr(pid))
		popen("kill -9 %s" % (pid))

	@classmethod
	def Info(cls, pid):
		status = Process.Status(pid)
		proc_pid = "/proc/%d" % (pid)
		if not os.path.exists(proc_pid):
			dict(
				pid=pid,
				exists=False,
				probeStart=cls.firstProbe,
				probeEnd=cls.lastProbe
			)
		else:
			status = Process.Status(pid)
			started = os.stat(proc_pid)[stat.ST_MTIME]
			running = time.time() - started
			# FIXME: Add process start time, end time, cpu %
			return dict(
				pid=pid,
				exists=True,
				f=count("/proc/%d/fd" % (pid)),
				tasks=count("/proc/%d/task" % (pid)),
				threads=int(status["threads"]),
				cmdline=cat("/proc/%d/cmdline" % (pid)),
				fdsize=status["fdsize"],
				vmsize=status["vmsize"],
				started=started,
				running=running
			)


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

# -----------------------------------------------------------------------------
#
# TMUX
#
# -----------------------------------------------------------------------------

class Tmux:
	"""A simple wrapper around the `tmux`  terminal multiplexer that allows to
	create sessions and windows and execute arbitrary code in it.
	
	This is particularly useful if you want to run command on remote servers
	but still want easy access to their detailed output/interact with them."""

	@classmethod
	def Run( self, params ):
		cmd = "tmux " + params
		res = popen(cmd)
		if isinstance(res, tuple):
			if res[1].find("failed to connect to server:") != -1:
				# there's not tmux session running so we just return nothing
				return ""
			else:
				raise Exception("Failed running command: {0}, exception: {1}".format(cmd, res))
		else:
			return res

	@classmethod
	def ListSessions( self ):
		return map(lambda _:_.split(":",1)[0].strip(), self.Run("list-session").split("\n"))
	
	@classmethod
	def EnsureSession( self, session ):
		if session not in self.ListSessions():
			self.Run("new-session -d -s " + session)
		return self

	@classmethod
	def ListWindows( self, session ):
		windows = filter(lambda _:_, self.Run("list-windows -t" + session).split("\n"))
		return map(lambda _:_.split(":",1)[1].split("[",1)[0].strip(), windows)

	@classmethod
	def EnsureWindow( self, session, name ):
		windows = self.ListWindows(session)
		if name not in windows:
			self.Run("new-window -t {0}:{1} -n {2}".format(session, len(windows), name))
		return self

	@classmethod
	def KillWindow( self, session, name ):
		if name in self.ListWindows(session):
			self.Run("kill-window -t {0}:{1}".format(session, name))

	@classmethod
	def Read( self, session, name ):
		return self.Run("capture-pane -t {0}:{1} \\; save-buffer -".format(session, name))

	@classmethod
	def Write( self, session, name, commands):
		self.Run("send-keys -t {0}:{1} {2} C-m".format(session, name, repr(commands)))

# -----------------------------------------------------------------------------
#
# UNITS
#
# -----------------------------------------------------------------------------
class Size:
	"""Converts the given value in the given units to bytes"""

	@classmethod
	def MB(cls, v):
		return cls.kB(v * 1024)

	@classmethod
	def kB(cls, v):
		return cls.B(v * 1024)

	@classmethod
	def B(cls, v):
		return v

class Time:
	"""Converts the given time in the given units to milliseconds"""

	@classmethod
	def w(cls, t):
		return cls.d(7 * t)

	@classmethod
	def d(cls, t):
		return cls.h(24 * t)

	@classmethod
	def h(cls, t):
		return cls.m(60 * t)

	@classmethod
	def m(cls, t):
		return cls.s(60 * t)

	@classmethod
	def s(cls, t):
		return cls.ms(t * 1000)

	@classmethod
	def ms(cls, t):
		return t

# -----------------------------------------------------------------------------
#
# RESULTS ENCAPSULATION
#
# -----------------------------------------------------------------------------

class Result:

	def __init__(self):
		pass

class Success(Result):
	"""Represents the success of a Rule."""

	def __init__(self, value=True, message=None):
		Result.__init__(self)
		self.message = message
		self.value = value
		self.duration = None

	def isSuccess( self ):
		return True

	def isFailure( self ):
		return False

	def __str__(self):
		return str(self.value)

	def __call__(self):
		return self.value


class Failure(Result):
	"""Represents the failure of a Rule."""

	def __init__(self, message="Failure", value=None):
		Result.__init__(self)
		self.message = message
		self.value = value
		self.duration = None

	def isSuccess( self ):
		return False

	def isFailure( self ):
		return True

	def __str__(self):
		return str(self.message)

	def __call__(self):
		return self.value


# -----------------------------------------------------------------------------
#
# SERVICE
#
# -----------------------------------------------------------------------------

class Service:
	"""A service is a collection of rules and actions. Rules are executed
	and actions are triggered according to the rules result."""

	# FIXME: Add a check() method that checks that actions exists for rules

	def __init__(self, name=None, monitor=(), actions={}):
		self.name    = name
		self.rules   = []
		self.runners = {}
		self.actions = {}
		if not (type(monitor) in (tuple, list)):
			monitor = tuple([monitor])
		map(self.addRule, monitor)
		self.actions.update(actions)

	def addRule(self, rule):
		self.rules.append(rule)

	def getAction(self, nameOrAction):
		"""Returns the action object with the given name."""
		if isinstance(nameOrAction, Action):
			return nameOrAction
		else:
			return self.actions[nameOrAction]

# -----------------------------------------------------------------------------
#
# RUNNER POOL
#
# -----------------------------------------------------------------------------

class Pool:
	"""Pools are used in Monitoring to limit the number of runners/rules executed
	at once. Pools have a maximum capacity, so that you can limit the numbers
	of elements you create."""

	def __init__(self, capacity):
		self.capacity = capacity
		self.elements = []

	def setCapacity( self, capacity ):
		self.capacity = capacity
		return self

	def add(self, element):
		if self.canAdd():
			self.elements.append(element)
			return True
		else:
			return False

	def canAdd(self):
		return len(self.elements) < self.capacity

	def remove(self, element):
		assert element in self.elements
		self.elements.remove(element)

	def size(self):
		return len(self.elements)

# -----------------------------------------------------------------------------
#
# RUNNER
#
# -----------------------------------------------------------------------------

class RunnerStillRunning(Exception):

	def __init__(self, runner):
		Exception.__init__(self, "Runner is still running: " + str(runner))
		self.runner = runner

class RunnerThreadPoolFull(Exception):

	def __init__(self, capacity):
		Exception.__init__(self, "Runner thread pool has reached full capacity (%s)" % (capacity))
		self.capacity = capacity


class Runner:
	"""Wraps a Rule or Action in a separate thread an invoked the 'onEnded'
	callback once the rule is executed."""

	POOL = Pool(50)

	@classmethod
	def Create(cls, runable, context=None, iteration=None, id=None):
		if Runner.POOL.canAdd():
			runner = Runner(runable, context, iteration, Runner.POOL, id=id)
			Runner.POOL.add(runner)
			return runner
		else:
			return None

	def __init__(self, runable, context=None, iteration=None, pool=None, id=None):
		assert isinstance(runable, Action) or isinstance(runable, Rule)
		self._onRunEnded  = None
		self.runable      = runable
		self.context      = context
		self.result       = None
		self.iteration    = iteration
		self.creationTime = now()
		self.startTime    = -1
		self.endTime      = -1
		self.duration     = 0
		self.pool         = pool
		self.id           = id
		self._thread      = threading.Thread(target=self._run)
		# We want the threads to be "daemonic", ie. they will all stop once
		# the main monitoring stops.
		# SEE: http://docs.python.org/release/2.5.2/lib/thread-objects.html
		self._thread.setDaemon(True)

	def getID( self ):
		return self.id

	def onRunEnded(self, callback):
		self._onRunEnded = callback
		return self

	def hasFailed(self):
		return not (isinstance(self.result, Success))

	def run(self, *args):
		self.args = args
		self._thread.start()
		return self

	def _run(self):
		self.startTime = now()
		try:
			self.result = self.runable.run(*self.args)
			if isinstance(self.result, Success) or isinstance(self.result, Failure):
				self.result.duration = self.duration
		except Exception, e:
			self.result = e
			Logger.Err("Exception occured in 'run' with: %s %s" % (e, self.runable))
			Logger.Traceback()
		self.endTime  = now()
		self.duration = self.endTime - self.startTime
		try:
			if self.pool:
				self.pool.remove(self)
		except Exception, e:
			Logger.Err("Exception occured in 'run/pool' with: %s %s" % (e, self.runable))
			Logger.Traceback()
		try:
			if self._onRunEnded:
				self._onRunEnded(self)
		except Exception, e:
			Logger.Err("Exception occured in 'run/onRunEnded' with: %s %s" % (e, self.runable))
			Logger.Traceback()


# -----------------------------------------------------------------------------
#
# MONITOR
#
# -----------------------------------------------------------------------------

class Monitor:
	"""The monitor is at the core of the Monitoring. Rules declared in registered
	services are run, and actions are executed according to the result."""

	FREQUENCY = Time.s(5)

	def __init__(self, *services):
		"""Creats a new monitor with the  given services."""
		self.services              = []
		self.isRunning             = False
		self.freq                  = self.FREQUENCY
		self.logger                = Logger(prefix="monitoring ")
		self.iteration             = 0
		self.iterationLastDuration = 0
		self.runners               = {}
		map(self.addService, services)

	def addService(self, service):
		"""Adds a service to this monitor."""
		self.services.append(service)
		return self

	def run(self, iterations=-1):
		"""Runs this Monitor for the given number of `iterations`. 
		If `iterations` is `-1` then the monitor will run indefinitely."""
		Signals.Setup()
		self.isRunning = True
		while self.isRunning:
			it_start = now()
			next_run = it_start + self.freq
			# For each registered service
			for service in self.services:
				# For each rule within the service
				for rule in service.rules:
					# We check if the rule has to be executed right now
					# or a little bit later
					to_wait = rule.shouldRunIn()
					if to_wait > 0:
						# If we have to wait, then we indicate what would
						# be the time to run the rule
						next_run = min(now() + to_wait, next_run)
					else:
						# The rule has to be run right now, so we try to get a
						# runner for it. This might fail if we can't create the
						# runner
						runner = self.getRunnerForRule(rule, service, self.iteration)
						if runner:
							rule.touch()
							runner.run()
						next_run = min(
							now() + rule.freq,
							next_run
						)
			# We've reached the end of an iteration
			duration                   = now() - it_start
			self.iterationLastDuration = duration
			self.logger.info(self.getStatusMessage())
			self.iteration             += 1
			# Sleeps waiting for the next run
			sleep_time = max(0, next_run - now())
			if sleep_time > 0:
				if sleep_time > 1000:
					self.logger.info("Sleeping for %0.2fs" % (sleep_time / 1000.0))
				time.sleep(sleep_time / 1000.0)
			# In case we've exceeded the number of iterations, we stop the loop
			if iterations > 0 and self.iteration >= iterations:
				self.isRunning = False

	def getRunnerForRule( self, rule, service, iteration ):
		try:
			return self._createRunner( rule, service, iteration, self.onRuleEnded )
		except RunnerStillRunning, e:
			if self.iteration - e.runner.iteration < 5:
				self.logger.err("Previous iteration's rule is still running: %s, you should increase its frequency." % (rule))
			else:
				self.logger.err("Previous iteration's rule %s seems to be still stuck after %s iteration." % (rule, e.runner.iteration - self.iteration))
			return None
		except RunnerThreadPoolFull, e:
			self.logger.err("Cannot create runner for rule: %s (thread pool reached full capacity)" % (rule))
			return None

	def getRunnerForAction( self, rule, action, service, iteration ):
		runner_id = "%s:%s" % (str(rule), str(action))
		try:
			return self._createRunner( action, service, iteration, self.onActionEnded, runner_id )
		except RunnerStillRunning, e:
			if self.iteration - e.runner.iteration < 5:
				self.logger.err("Previous iteration's action is still running: %s.%s, you should increase its frequency." % (rule, str(action)))
			else:
				self.logger.err("Previous iteration's action %s.%s seems to be still stuck after %s iteration." % (rule, str(action), e.runner.iteration - self.iteration))
			return None
		except RunnerThreadPoolFull, e:
			self.logger.err("Cannot create runner for action: %s.%s (thread pool reached full capacity)" % (rule, str(action)))
			return None

	def onRuleEnded(self, runner):
		"""Callback bound to 'Runner.onRunEnded', trigerred once a rule was executed.
		If the rule failed, actions will be executed."""
		rule      = runner.runable
		service   = runner.context
		iteration = runner.iteration
		if isinstance(runner.result, Success):
			if rule.success:
				for action in rule.success:
					action_object = service.getAction(action)
					action_runner = self.getRunnerForAction(rule, action_object, service, self.iteration)
					if action_runner:
						action_runner.run(self, service, rule, runner)
		elif isinstance(runner.result, Failure):
			self.logger.err("Failure on ", rule, ":", runner.result)
			if rule.fail:
				#self.logger.info("Failure actions:", ", ".join(rule.fail))
				for action in rule.fail:
					action_object = service.getAction(action)
					action_runner = self.getRunnerForAction(rule, action_object, service, self.iteration)
					if action_runner:
						action_runner.run(self, service, rule, runner)
			else:
				#self.logger.info("No failure action to trigger")
				pass
		else:
			self.logger.err("Rule did not return Success or Failure instance: %s, got %s" % (rule, runner.result))
		# We unregister the runnner
		del self.runners[runner.getID()]
	
	def onActionEnded( self, runner ):
		# We unregister the runnner
		del self.runners[runner.getID()]

	def _createRunner(self, runable, context, iteration, callback, runableId=None):
		"""Creates a runner for the given runable, making sure that it won't
		be started twice, raising `RunnerStillRunning` 
		or `RunnerThreadPoolFull` in case of problems."""
		# FIXME: we should prefix the ID with the Rule name, if any
		if runableId is None:
			runable_id = str(runable)
		else:
			runable_id = runableId
		if runable_id in self.runners:
			runner = self.runners[runable_id]
			raise RunnerStillRunning(runner)
		else:
			runner = Runner.Create(runable, context=context, iteration=iteration, id=runable_id)
			if runner:
				self.runners[runner.getID()] = runner
				runner.onRunEnded(callback)
				return runner
			else:
				raise RunnerThreadPoolFull(Runner.POOL.capacity)

	def getStatusMessage(self):
		return "#%d (runners=%d,threads=%d,duration=%0.2fs)" % (self.iteration, Runner.POOL.size(), threading.activeCount(), self.iterationLastDuration)

# -----------------------------------------------------------------------------
#
# GLOBALS
#
# -----------------------------------------------------------------------------

SUCCESS = Success()
FAILURE = Failure()
# Updates the CPU stats so that CPUUsage works
System.CPUStats()

def command(args):
	if len(args) != 1:
		print "Usage: monitoring FILE"
	else:
		with file(args[0],"r") as f:
			exec f.read() 

# EOF - vim: tw=80 ts=4 sw=4 noet
