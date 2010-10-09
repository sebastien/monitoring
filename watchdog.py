#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Watchdog
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   10-Feb-2010
# Last mod.         :   29-Sep-2010
# -----------------------------------------------------------------------------

import re, sys, os, time, datetime, stat
import httplib, socket, threading, signal, subprocess, glob

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
#  File "/home/sebastien/Projects/Local/lib/python/watchdog.py", line 669, in run
#    Runner(rule,context=service,iteration=self.iteration).onRunEnded(self.onRuleEnded).run()
#  File "/home/sebastien/Projects/Local/lib/python/watchdog.py", line 620, in run
#    self._thread.start()
#  File "/usr/lib/python2.6/threading.py", line 474, in start
#    _start_new_thread(self.__bootstrap, ())
#thread.error: can't start new thread

__version__ = "0.9.1"

RE_SPACES  = re.compile("\s+")
RE_INTEGER = re.compile("\d+")

def cat( path ):
	"""Outputs the content of the file at the given path"""
	f = file(path, 'r')
	d = f.read()
	f.close()
	return d

def count( path ):
	"""Count the number of files and directories at the given path"""
	return len(os.listdir(path))

def now():
	"""Returns the current time in milliseconds"""
	return time.time() * 1000

def popen( command, cwd=None ):
	"""Returns the stdout from the given command, using the subproces
	command."""
	cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, cwd=cwd)
	res = cmd.stdout.read()
	cmd.wait()
	return res

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
	def Setup( self ):
		"""Sets up the shutdown signal handlers."""
		if self.SINGLETON is None: self.SINGLETON = Signals()
		self.SINGLETON.setup()
	
	@classmethod
	def OnShutdown( self, callback ):
		"""Registers a new callback to be triggered on
		SIGINT/SIGHUP/SIGABRT/SIQUITE/SIGTERM."""
		if self.SINGLETON is None: self.SINGLETON = Signals()
		assert not self.SINGLETON.signalsRegistered, "OnShutdown must be called before Setup."
		self.SINGLETON.onShutdown.append(callback)

	def __init__( self ):
		self.signalsRegistered  = []
		self.onShutdown         = []
		try:
			import signal
			self.hasSignalModule = True
		except:
			self.hasSignalModule = False

	def setup( self ):
		"""Sets up the signals, registering the shutdown function. You only
		need to call this function once."""
		if self.hasSignalModule and not self.signalsRegistered:
			# Jython does not support all signals, so we only use
			# the available ones
			signals = ['SIGINT',  'SIGHUP', 'SIGABRT', 'SIGQUIT', 'SIGTERM']
			import signal
			for sig in signals:
				try:
					signal.signal(getattr(signal,sig), self._shutdown)
					self.signalsRegistered.append(sig)
				except Exception, e:
					Logger.Err("[!] watchdog.Signals._registerSignals:%s %s\n" % (sig, e))

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
	def I( self ):
		if self.SINGLETON is None: self.SINGLETON = Logger()
		return self.SINGLETON
	@classmethod
	def Err ( self, *message ): self.I().err(*message)
	@classmethod
	def Warn( self, *message ): self.I().warn(*message)
	@classmethod
	def Info( self, *message ): self.I().info(*message)
	@classmethod
	def Sep( self ):  self.I().sep()
	@classmethod
	def Output( self, *message ): self.I().output(*message)

	def __init__( self, stream=sys.stdout, prefix="" ):
		self.stream  = stream
		self.lock    = threading.RLock()
		self.prefix  = prefix

	def err( self, *message ):
		self("[!]", *message)

	def warn( self, *message ):
		self("[-]", *message)

	def info( self, *message ):
		self("---", *message)

	def output( self, *message ):
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
	
	def sep( self ):
		self.lock.acquire()
		self.stream.write("\n")
		self.stream.flush()
		self.lock.release()

	def __call__( self, prefix, *message ):
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
		"[^.]+",  "(\d+)", "(\d+)", "\d+", "\d+", "\d+", "\d+", "\d?\d\:\d\d", "[^ ]+", "\d\d\:\d\d\:\d\d", "(.+)"
	])))

	@classmethod
	def Find( self, command, compare=(lambda a,b: a == b) ):
		# FIXME: Probably better to direcly use List()
		# The output looks like this
		# 1000      2446     1 12 84048 82572   0 14:02 ?        00:04:08 python /usr/lib/exaile/exaile.py --datadir=/usr/share/exaile/data --startgui
		# 1000      2472     1  0  2651  3496   0 14:02 ?        00:00:00 /usr/lib/gvfs/gvfsd-http --spawner :1.6 /org/gtk/gvfs/exec_spaw/2
		# 107       2473     1  0  4274  4740   0 14:02 ?        00:00:00 /usr/sbin/hald
		# root      2474  2473  0   883  1292   1 14:02 ?        00:00:00 hald-runner
		# root      2503  2474  0   902  1264   1 14:02 ?        00:00:00 hald-addon-input: Listening on /dev/input/event10 /dev/input/event4 /dev/input/event11 /dev/input/event9 /dev/in
		# root      2508  2474  0   902  1228   0 14:02 ?        00:00:00 /usr/lib/hal/hald-addon-rfkill-killswitch
		# root      2516  2474  0   902  1232   1 14:02 ?        00:00:00 /usr/lib/hal/hald-addon-leds

		# Note: we skip the header and the trailing EOL
		for line in popen("ps -AF").split("\n")[1:-1]:
			match = self.RE_PS_OUTPUT.match(line)
			if match:
				pid  = match.group(1)
				ppid = match.group(2)
				cmd  = match.group(3)
				if compare(command, cmd):
					return (pid, ppid, cmd)
			else:
				Logger.Err("Problem with PS output !: " + repr(line))
		return None

	@classmethod
	def List( self ):
		"""Returns a map of pid to cmdline"""
		res = {}
		for p in glob.glob("/proc/*/cmdline"):
			process = p.split("/")[2]
			if process != "self":
				res[int(process)] = cat(p)
		return res
		
	@classmethod
	def GetWith( self, expression, compare=(lambda a,b:a.find(b) >= 0) ):
		"""Returns a list of all processes that contain the expression
		in their command line."""
		res = []
		for pid, cmdline in self.List().items():
			if compare(cmdline, expression):
				res.append(pid)
		return res

	@classmethod
	def Status( self,pid ):
		res = {}
		pid = int(pid)
		for line in cat("/proc/%d/status" % (pid)).split("\n"):
			if not line: continue
			name, value = line.split(":", 1)
			res[name.lower()] = value.strip()
		return res

	
	@classmethod
	def Start( self, command, cwd=None ):
		# FIXME: Not sure if we need something like & at the end
		command += ""
		Logger.Info("Starting process: " + repr(command))
		popen(command, cwd)

	@classmethod
	def Kill( self, pid ):
		Logger.Info("Killing process: " + repr(pid))
		popen("kill -9 %s" % (pid))

	@classmethod
	def Info( self, pid ):
		status   = Process.Status(pid)
		proc_pid = "/proc/%d" % (pid)
		if not os.path.exists(proc_pid):
			dict(
				pid         = pid,
				exists      = False,
				probeStart  = self.firstProbe,
				probeEnd    = self.lastProbe
			)
		else:
			status  = Process.Status(pid)
			started = os.stat(proc_pid)[stat.ST_MTIME]
			running = time.time() - started
			# FIXME: Add process start time, end time, cpu %
			return dict(
				pid      = pid,
				exists   = True,
				fd       = count("/proc/%d/fd"      % (pid)),
				tasks    = count("/proc/%d/task"    % (pid)),
				threads  = status["threads"],
				cmdline  = cat  ("/proc/%d/cmdline" % (pid)),
				fdsize   = status["fdsize"],
				vmsize   = status["vmsize"],
				started  = started,
				running  = running
			)

# -----------------------------------------------------------------------------
#
# PROCESS INFORMATION
#
# -----------------------------------------------------------------------------

class System:
	"""A collection of utilities to interact with system information"""
	
	LAST_CPU_STAT = None

	@classmethod
	def MemoryInfo( self ):
		"""Returns the content of /proc/meminfo as a dictionary 'key' -> 'value'
		where value is in kB"""
		res = {}
		for line in cat("/proc/meminfo").split("\n")[:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			print repr(line)
			name, value = line[:2]
			res[name.replace("(","_").replace(")","_").replace(":","")] = int(value)
		return res
	
	@classmethod
	def MemoryUsage( self ):
		"""Returns the memory usage (between 0.0 and 1.0) on this system."""
		meminfo = self.MemoryInfo()
		return (meminfo["MemTotal"] - meminfo["MemFree"]) / float (meminfo["MemTotal"])

	@classmethod
	def DriveUsage( self ):
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
		for line in popen("df -iP").split("\n")[1:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			system, inodes, used_inodes, free_inodes, usage, mount = line
			res[mount] = float(usage[:-1]) / 100.0
		return res

	@classmethod
	def CPUStats( self ):
		"""Returns  CPU stats, that can be used to get the CPUUsage"""
		# From <http://ubuntuforums.org/showthread.php?t=148781>
		time_list = cat("/proc/stat").split("\n")[0].split(" ")[2:6]
		res       = map(int, time_list)
		self.LAST_CPU_STAT = res
		return res
	
	@classmethod
	def CPUUsage( self, cpuStat=None ):
		if not cpuStat: cpuStat = self.LAST_CPU_STAT
		stat_now = self.CPUStats()
		res      = []
		for i in range(len(cpuStat)): res.append( stat_now[i] - cpuStat[i] )
		usage = 100 - (res[len(res) - 1] * 100.00 / sum(res))
		return usage

	@classmethod
	def GetInterfaceStats( self ):
		# $/proc/net$ sudo cat dev
		# Inter-|   Receive                                                |  Transmit
		#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
		#     lo:454586083  954504    0    0    0     0          0         0 454586083  954504    0    0    0     0       0          0
		#   eth0:55735297   85080    0    0    0     0          0         0  5428643   67978    0    0    0     0       0          0
		#   eth1:3300079052153 11645531967    0 8098    0     0          0         0 3409466791555 6131411252    0    0    0     0       0          0
		#  edge0:       0       0    0    0    0     0          0         0     9763      87    0    0    0     0       0          0
		res = {}
		for line in cat("/proc/net/dev").split("\n")[2:-1]:
			interface, stats = RE_SPACES.sub(" ", line).strip().split(":",1)
			stats            = map(long, stats.strip().split(" "))
			rx_bytes, rx_pack, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compr, rx_multicast, \
			tx_bytes, tx_pack, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed = stats
			res[interface] = {
				"rx" : dict (
					bytes=rx_bytes,
					packets=rx_pack,
					errors=rx_errs,
					drop=rx_drop
				),
				"tx" : dict (
					bytes=tx_bytes,
					packets=tx_pack,
					errors=tx_errs,
					drop=tx_drop
				),
				"total" : dict (
					bytes  =tx_bytes + rx_bytes,
					packets=tx_pack  + rx_pack,
					errors =tx_errs  + rx_errs,
					drop   =tx_drop  + rx_drop
				)
			}
		return res

# -----------------------------------------------------------------------------
#
# UNITS
#
# -----------------------------------------------------------------------------

class Size:
	"""Converts the given value in the given units to bytes"""

	@classmethod
	def MB(self, v):
		return self.kB(v * 1024)

	@classmethod
	def kB(self, v):
		return self.B(v * 1024)

	@classmethod
	def B(self, v):
		return v


class Time:
	"""Converts the given time in the given units to milliseconds"""

	@classmethod
	def m(self, t ):
		return self.s(60 * t)

	@classmethod
	def s(self, t ):
		return self.ms(t * 1000)

	@classmethod
	def ms(self, t ):
		return t

# -----------------------------------------------------------------------------
#
# RESULTS ENCAPSULATION
#
# -----------------------------------------------------------------------------

class Result:
	def __init__( self ):
		pass

class Success(Result):
	"""Represents the success of a Rule."""

	def __init__(self, value=True, message=None):
		Result.__init__(self)
		self.message  = message
		self.value    = value
		self.duration = None
	
	def __str__( self ):
		return str(self.value)
	
	def __call__( self ):
		return self.value

class Failure(Result):
	"""Represents the failure of a Rule."""

	def __init__(self, message="Failure", value=None):
		Result.__init__(self)
		self.message  = message
		self.value    = value
		self.duration = None
	
	def __str__( self ):
		return str(self.message)

	def __call__( self ):
		return self.value



# -----------------------------------------------------------------------------
#
# ACTIONS
#
# -----------------------------------------------------------------------------

class Action:
	"""Represents actions that can be triggered on rule sucess or failure."""

	def __init__( self ):
		pass
	
	def run( self, monitor, service, rule, runner ):
		pass

class Log(Action):
	"""Logs results to the given path."""

	def __init__( self, path=None, stdout=True ):
		Action.__init__(self)
		self.path   = path
		self.stdout = stdout
	
	def preamble( self, monitor, service, rule, runner ):
		return "%s %s[%d]" % (timestamp(), service and service.name, runner.iteration)

	def successMessage( self, monitor, service, rule, runner ):
		return "%s --- %s succeeded (in %0.2fms)" % (self.preamble(monitor,service,rule,runner), runner.runnable, runner.duration)

	def failureMessage( self, monitor, service, rule, runner ):
		return "%s [!] %s of %s (in %0.2fms)" % (self.preamble(monitor,service,rule,runner), runner.result, runner.runnable, runner.duration)
	
	def run( self, monitor, service, rule, runner):
		if runner.hasFailed():
			msg = self.failureMessage(monitor, service, rule, runner) + "\n"
		else:
			msg = self.successMessage(monitor, service, rule, runner) + "\n"
		if self.stdout:
			sys.stdout.write(msg)
		if self.path:
			f = file( self.path, 'a')
			f.write(msg)
			f.flush()
			f.close()
		return True

class LogResult(Log):

	def __init__( self, message, path=None, stdout=True, process=lambda _:_ ):
		Log.__init__(self, path, stdout)
		self.message   = message
		self.processor = process

	def successMessage( self, monitor, service, rule, runner ):
		return "%s %s %s" % (self.preamble(monitor, service, rule, runner), self.message, self.processor(runner.result))

class Restart(Action):

	def __init__( self, command, cwd=None ):
		self.command = command
		self.cwd     = cwd
	
	def run( self, monitor, service, rule, runner ):
		process_info = Process.Find(self.command)
		if not process_info:
			Process.Start(self.command, cwd=cwd)
		else:
			pid, ppid, cmd = process_info
			Process.Kill(pid=pid)
			Process.Start(cmd, cwd=cwd)
		return True

# -----------------------------------------------------------------------------
#
# RULES
#
# -----------------------------------------------------------------------------

class Rule:
	"""Rules return either a Sucess or Failure when run, and take actions
	as 'fail' or 'success' arguments, which will be triggered by the
	watchdog service."""

	COUNT = 0

	def __init__( self, freq, fail=(), success=() ):
		self.id      = Rule.COUNT
		Rule.COUNT   += 1
		self.lastRun = 0
		self.freq    = freq
		self.fail    = fail
		self.success = success
	
	def shouldRunIn( self ):
		since_last_run = now() - self.lastRun
		return self.freq - since_last_run 

	def run( self ):
		self.lastRun = now()
		return Success()

class HTTP(Rule):

	def __init__( self, GET=None, POST=None, timeout=Time.s(10), freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		url    = None
		method = None
		if GET:
			url = GET
			method = "GET"
		if POST:
			url = POST
			method = "POST"
		if url.startswith("http://"): url = url[7:]
		server, uri  = url.split("/",  1)
		if not uri.startswith("/"): uri = "/" + uri
		if server.find(":") >= 0:
			server, port = server.split(":", 1)
		else:
			port = 80
		self.server  = server
		self.port    = port
		self.uri     = uri
		self.body    = ""
		self.headers = None
		self.method  = "GET"
		self.timeout = timeout / 1000.0

	def run( self ):
		Rule.run(self)
		conn = httplib.HTTPConnection(self.server, self.port, timeout=self.timeout)
		res  = None
		try:
			conn.request(self.method, self.uri, self.body, self.headers or {})
			resp = conn.getresponse()
			res  = resp.read()
		except socket.error, e:
			return Failure("Socket error: %s" % (e))
		if resp.status >= 400:
			return Failure("HTTP response has error status %s" % (resp.status))
		else:
			return Success(res)
	
	def __repr__( self ):
		return "HTTP(%s=\"%s:%s/%s\",timeout=%s)" % (self.method, self.server, self.port, self.uri, self.timeout)

class Mem(Rule):

	def __init__( self, max, freq=Time.m(1), fail=(), success=() ):
		Rule.__init__(self, freq, fail, success)
		self.max = max
		pass

	def run( self ):
		Rule.run(self)
		return Success()

	def __repr__( self ):
		return "Mem(max=Size.b(%s), freq.Time.ms(%s))" % (self.max, self.freq)

class Delta(Rule):
	"""Executes a rule and extracts a numerical value out of it, successfully returning
	when at least two values have been extracted from the given rule."""

	def __init__( self, rule, extract=lambda _:_, fail=(), success=() ):
		Rule.__init__(self, rule.freq, fail, success)
		self.extractor = extract
		self.rule      = rule
		self.previous  = None

	def run( self ):
		res = self.rule.run()
		if isinstance(res, Success):
			value = self.extractor(res.value)
			if self.previous is None:
				self.previous = value
				return Failure("Not enough history yet")
			else:
				delta = value - self.previous
				self.previous = value
				return Success(delta)
		else:
			return res

# -----------------------------------------------------------------------------
#
# SERVICE
#
# -----------------------------------------------------------------------------

class Service:
	"""A service is a collection of rules and actions. Rules are executed
	and actions are triggered according to the rules result."""

	# FIXME: Add a check() method that checks that actions exists for rules

	def __init__( self, name=None, monitor=(), actions={} ):
		self.name    = name
		self.rules   = []
		self.actions = {}
		map(self.addRule, monitor)
		self.actions.update(actions)
	
	def addRule( self, rule ):
		self.rules.append(rule)
	
	def getAction( self, nameOrAction ):
		"""Returns the action object with the given name."""
		if isinstance(nameOrAction, Action):
			return nameOrAction
		else:
			return self.actions[nameOrAction]

	def act( self, name, event ):
		"""Runs the action with the given name."""
		assert self.actions.has_key(name)
		# NOTE: Document the protocol
		# FIXME: Use pools ?
		runner = Runner.Create(self.actions[name])
		if runner:
			runner.run(event, self)
		else:
			Logger.Err("Cannot execute action because Runner.POOL is full: %s" % (self))

# -----------------------------------------------------------------------------
#
# RUNNER
#
# -----------------------------------------------------------------------------

# FIXME: Nos sure if pools are really necessary, they're not used so far
class Pool:
	"""Pools are used in Watchdog to limit the number of runners/rules executed
	at once. Pools have a maximum capacity, so that you can limit the numbers
	of elements you create."""

	def __init__( self, capacity ):
		self.capacity = capacity
		self.elements = []

	def add( self, element ):
		if self.canAdd():
			self.elements.append(element)
			return True
		else:
			return False

	def canAdd( self ):
		return len(self.elements) < self.capacity

	def remove( self, element ):
		assert element in self.elements
		self.elements.remove(element)
	
	def size( self ):
		return len(self.elements)

class Runner:
	"""Wraps a Rule or Action in a separate thread an invoked the 'onEnded'
	callback once the rule is executed."""

	POOL = Pool(100)

	@classmethod
	def Create( self, runnable, context=None, iteration=None):
		if Runner.POOL.canAdd():
			runner = Runner(runnable, context, iteration, Runner.POOL)
			Runner.POOL.add(runner)
			return runner
		else:
			return None

	def __init__( self, runnable, context=None, iteration=None, pool=None ):
		assert isinstance(runnable, Action) or isinstance(runnable, Rule)
		self._onRunEnded  = None
		self.runnable     = runnable
		self.context      = context
		self.result       = None
		self.iteration    = iteration
		self.creationTime = now()
		self.startTime    = -1
		self.endTime      = -1
		self.duration     = 0
		self.pool         = pool
		self._thread      = threading.Thread(target=self._run)

	def onRunEnded( self, callback ):
		self._onRunEnded = callback
		return self

	def hasFailed( self ):
		return not (isinstance(self.result, Success))

	def run( self, *args ):
		self.args = args
		self._thread.start()
		return self

	def _run( self ):
		self.startTime = now()
		try:
			self.result = self.runnable.run(*self.args)
			if isinstance(self.result, Success) or isinstance(self.result, Failure):
				self.result.duration = self.duration
		except Exception, e:
			self.result = e
			# FIXME: Rewrite this properly
			Logger.Err("Exception occured in 'run' with: %s %s" % (e, self.runnable))
		self.endTime  = now()
		self.duration = self.endTime - self.startTime
		try:
			if self.pool: self.pool.remove(self)
		except Exception, e:
			Logger.Err("Exception occured in 'run/pool' with: %s %s" % (e, self.runnable))
		try:
			if self._onRunEnded:
				self._onRunEnded(self)
		except Exception, e:
			Logger.Err("Exception occured in 'run/onRunEnded' with: %s %s" % (e, self.runnable))

# -----------------------------------------------------------------------------
#
# MONITOR
#
# -----------------------------------------------------------------------------

class Monitor:
	"""The monitor is at the core of the watchdog. Rules declared in registered
	services are run, and actions are executed according to the result."""

	FREQUENCY = Time.s(5)

	def __init__( self, *services ):
		self.services   = []
		self.isRunning  = False
		self.freq       = self.FREQUENCY
		self.logger     = Logger(prefix="watchdog ")
		self.iteration  = 0
		self.runners    = {}
		map(self.addService, services)
	
	def runnerForRule(self, rule, context, iteration):
		if self.runners.has_key(rule.id):
			self.logger.err("Previous iteration's rule is still running: %s, you should increase its frequency." % (rule))
			return None
		else:
			runner = Runner.Create(rule,context=context,iteration=iteration)
			self.runners[runner.runnable.id] = True
			if runner:
				runner.onRunEnded(self.onRuleEnded)
				return runner
			else:
				self.logger.err("Cannot create runner for rule: %s (thread pool reached full capacity)" % (rule))

	def addService( self, service ):
		self.services.append(service)

	def run( self ):
		Signals.Setup()
		self.isRunning = True
		while self.isRunning:
			it_start = now()
			next_run = it_start + self.freq
			for service in self.services:
				for rule in service.rules:
					to_wait = rule.shouldRunIn()
					if to_wait > 0:
						next_run = min(now() + to_wait, next_run)
					else:
						# Create a runner
						runner = self.runnerForRule(rule,service,self.iteration)
						if runner:
							runner.run()
						else:
							# FIXME: Rule should fail because it can't be
							# executed
							pass
						next_run = min(
							now() + rule.freq,
							next_run
						)
			duration = now() - it_start
			self.logger.info("#%d (runners=%d,threads=%d,duration=%0.2fs)" % (self.iteration, Runner.POOL.size(), threading.activeCount(), duration))
			self.iteration += 1
			# Sleeps waiting for the next run
			sleep_time = max(0, next_run - now())
			if sleep_time > 0:
				if sleep_time > 1000:
					self.logger.info("Sleeping for %0.2fs" % (sleep_time / 1000.0))
				time.sleep(sleep_time / 1000.0)

	def onRuleEnded( self, runner ):
		"""Callback bound to 'Runner.onRunEnded', trigerred once a rule was executed.
		If the rule failed, actions will be executed."""
		# FIXME: Handle exception
		rule    = runner.runnable
		service = runner.context
		if isinstance(runner.result, Success):
			if rule.success:
				#self.logger.info("Success actions:", ", ".join(rule.success))
				for action in rule.success:
					action_object = service.getAction(action)
					action_runner = Runner.Create(action_object)
					if action_runner:
						action_runner.run(runner, service, rule, runner)
					else:
						self.logger.err("Cannot create action runner for: %s" % (action_object))
		elif isinstance(runner.result, Failure):
			self.logger.err("Failure on ", rule, ":", runner.result)
			if rule.fail:
				#self.logger.info("Failure actions:", ", ".join(rule.fail))
				for action in rule.fail:
					action_object = service.getAction(action)
					action_runner = Runner.Create(action_object)
					if action_runner:
						action_runner.run(runner, service, rule, runner)
					else:
						self.logger.err("Cannot create action runner for: %s" % (action_object))
			else:
				self.logger.info("No failure action to trigger")
		else:
			self.logger.err("Rule did not return Success or Failure instance: %s, got %s" % (rule, runner.result))
		# We unregister the runnner
		del self.runners[rule.id]

# Globals

SUCCESS = Success()
FAILURE = Failure()
# Updates the CPU stats so that CPUUsage works
System.CPUStats()

# EOF - vim: tw=80 ts=4 sw=4 noet
