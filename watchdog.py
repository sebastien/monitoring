#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Watchdog
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   10-Feb-2010
# Last mod.         :   09-Sep-2010
# -----------------------------------------------------------------------------

import re, sys, os, time, datetime, stat
import httplib, socket, threading, signal, subprocess, glob

# FIXME: Prevent flooding of taskrunner, ie. when tasks take longer than
# their duration

# FIXME: Ensure re-ordering of logging

__version__ = "0.9.1"

RE_SPACES  = re.compile("\s+")
RE_INTEGER = re.compile("\d+")

def cat( path ):
	f = file(path, 'r')
	d = f.read()
	f.close()
	return d

def count( path ):
	return len(os.listdir(path))

def now():
	return time.time() * 1000

def popen( command, cwd=None ):
	cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, cwd=cwd)
	res = cmd.stdout.read()
	cmd.wait()
	return res

def timestamp():
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

	SINGLETON = None

	@classmethod
	def Setup( self ):
		"""Sets up the shutdown signal handlers."""
		if self.SINGLETON is None: self.SINGLETON = Signals()
		self.SINGLETON.setup()
	
	@classmethod
	def OnShutdown( self, callback ):
		"""Registers a new ."""
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
		"""Sets up the signals."""
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

class System:
	
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

class Size:

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

class Success:

	def __init__(self, value=True, message=None):
		self.message  = message
		self.value    = value
		self.duration = None
	
	def __str__( self ):
		return str(self.value)

class Failure:

	def __init__(self, message="Failure", value=None):
		self.message  = message
		self.value    = value
		self.duration = None
	
	def __str__( self ):
		return str(self.message)

SUCCESS = Success()
FAILURE = Failure()


# -----------------------------------------------------------------------------
#
# ACTIONS
#
# -----------------------------------------------------------------------------

class Action:

	def __init__( self ):
		pass
	
	def run( self, monitor, service, rule, runner ):
		pass

class Log(Action):

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
		return True

# -----------------------------------------------------------------------------
#
# RULES
#
# -----------------------------------------------------------------------------

class Rule:

	def __init__( self, freq, fail, success=() ):
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
		if url.startswith("http://"): url = url[6:]
		server, uri  = url.split("/",  1)
		if not uri.startswith("/"): uri = "/" + uri
		server, port = server.split(":", 1)
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

	# FIXME: Add a check() method that checks that actions exists for rules

	def __init__( self, name, monitor=(), actions={} ):
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
		Runner(self.actions[name]).run(event, self)

# -----------------------------------------------------------------------------
#
# RUNNER
#
# -----------------------------------------------------------------------------

class Runner:
	"""Wraps a Rule or Action in a separate thread an invoked the 'onEnded'
	callback once the rule is executed."""

	def __init__( self, runnable, context=None, iteration=None ):
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
			self.result.duration = self.duration
		except Exception, e:
			self.result = e
			# FIXME: Rewrite this properly
			Logger.Err("Exception occured in 'run' with:", self.runnable, e)
		self.endTime = now()
		self.duration = self.endTime - self.startTime
		if self._onRunEnded: self._onRunEnded(self)

# -----------------------------------------------------------------------------
#
# MONITOR
#
# -----------------------------------------------------------------------------

class Monitor:

	FREQUENCY = Time.s(5)

	def __init__( self, *services ):
		self.services  = []
		self.isRunning = False
		self.freq      = self.FREQUENCY
		self.logger    = Logger(prefix="watchdog ")
		self.iteration = 0
		map(self.addService, services)
	
	def addService( self, service ):
		self.services.append(service)

	def run( self ):
		Signals.Setup()
		self.isRunning = True
		while self.isRunning:
			next_run = now() + self.freq
			for service in self.services:
				for rule in service.rules:
					to_wait = rule.shouldRunIn()
					if to_wait > 0:
						next_run = min(now() + to_wait, next_run)
					else:
						# FIXME: Should go through a rule runner
						Runner(rule,context=service,iteration=self.iteration).onRunEnded(self.onRuleEnded).run()
						next_run = min(
							now() + rule.freq,
							next_run
						)
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
					service.getAction(action).run(runner, service, rule, runner)
		elif isinstance(runner.result, Failure):
			self.logger.err("Failure on ", rule, ":", runner.result)
			if rule.fail:
				#self.logger.info("Failure actions:", ", ".join(rule.fail))
				for action in rule.fail:
					service.getAction(action).run(runner, service, rule, runner)
			else:
				self.logger.info("No failure action to trigger")
		else:
			self.logger.err("Rule did not return Success or Failure instance: %s, got %s" % (rule, runner.result))

# EOF - vim: tw=80 ts=4 sw=4 noet
