#!/usr/bin/env python

import sys, os, time, datetime, httplib, socket, threading, signal

# Jython has no signal module
SIGNALS_REGISTERED  = False
SIGNALS_ON_SHUTDOWN = []
try:
	import signal
	HAS_SIGNAL = True
except:
	HAS_SIGNAL = False

def cat( path ):
	f = file(path, 'r')
	d = f.read()
	f.close()
	return d

def count( path ):
	return len(os.path.listdir(path))

def now():
	return time.time() * 1000

def shutdown(*args):
	for callback in SIGNALS_ON_SHUTDOWN:
		try:
			callback()
		except:
			pass
	sys.exit()

def registerSignals():
	global SIGNALS_REGISTERED
	if HAS_SIGNAL and SIGNALS_REGISTERED:
		# Jython does not support all signals, so we only use
		# the available ones
		signals = ['SIGINT',  'SIGHUP', 'SIGABRT', 'SIGQUIT', 'SIGTERM']
		for sig in signals:
			try:
				signal.signal(getattr(signal,sig),shutdown)
			except Exception, e:
				sys.stderr.write("[!] watchdog.registerSignals:%s %s\n" % (sig, e))
		SIGNALS_REGISTERED = True

class Logger:

	def __init__( self, stream=sys.stdout ):
		self.stream = stream
		self.lock    = threading.RLock()

	def err( self, *message ):
		self("[!]", *message)

	def warn( self, *message ):
		self("[-]", *message)

	def info( self, *message ):
		self("---", *message)
	
	def sep( self ):
		self.lock.acquire()
		self.stream.write("\n")
		self.stream.flush()
		self.lock.release()

	def __call__( self, prefix, *message ):
		self.lock.acquire()
		message = " ".join(map(str, message))
		n       = datetime.datetime.now()
		self.stream.write("%04d-%02d-%02dT%02d:%02d:%02d %s %s\n" % (
			n.year, n.month, n.day, n.hour, n.minute, n.second,
			prefix, message
		))
		self.stream.flush()
		self.lock.release()

class ProcessInfo:
	# See <http://linux.die.net/man/5/proc>

	@classmethod
	def List( self ):
		"""Returns a map of pid to cmdline"""
		res = {}
		for p in glob.glob("/proc/*/cmdline"):
			res[int(p.split("/")[2])] = cat(p)
		return res
		
	@classmethod
	def GetWith( self, expression ):
		"""Returns a list of all processes that contain the expression
		in their command line."""
		res = []
		for pid, cmdline in self.List().items():
			if cmdline.find(expression) != -1:
				res.append(pid)
		return res

	@classmethod
	def Status( self,pid ):
		res = {}
		for line in cat("/proc/%d/status" % (pid)).split("\n"):
			name, value = line.split(":", 1)
			res[name.lower()] = value.strip()
		return res

	def __init__( self ):
		self.probeStart = 0

	def info( self, pid ):
		status = ProcessInfo.Status(pid)
		if self.probeStart == 0:
			self.probeStart = now()
		if os.path.exists("/proc/%d"):
			dict(
				pid         = pid,
				exists      = False,
				probeStart  = self.firstProbe,
				probeEnd    = self.lastProbe
			)
		else:
			self.probeEnd = now()
			status = ProcessInfo.Status("/proc/%d/status" % (pid)),
			# FIXME: Add process start time, end time, cpu %
			dict(
				pid      = pid,
				exists   = True,
				fd       = count("/proc/%d/fd"      % (pid)),
				tasks    = count("/proc/%d/task"    % (pid)),
				threads  = status["threads"],
				cmdline  = cat  ("/proc/%d/cmdline" % (pid)),
				fdsize   = status["fdsize"],
				vmsize   = status["vmsize"],
				vmpeak   = status["vmspeak"],
				probeStart = self.firstProbe,
				probeEnd   = self.lastProbe
			)

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

class Rule:

	def __init__( self, freq, fail ):
		self.lastRun = 0
		self.freq    = freq
		self.fail    = fail
	
	def shouldRunIn( self ):
		return self.freq - (now() - self.lastRun)

	def run( self ):
		self.lastRun = now()
		return True

class HTTP(Rule):

	def __init__( self, GET=None, POST=None, timeout=Time.s(10), freq=Time.m(1), fail=()):
		Rule.__init__(self, freq, fail)
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
		try:
			conn.request(self.method, self.uri, self.body, self.headers or {})
			resp = conn.getresponse()
			res  = resp.read()
		except socket.error:
			return False
		if resp.status >= 400:
			return False
		else:
			return True
	
	def __repr__( self ):
		return "HTTP(%s=\"%s:%s/%s\",freq=Time.ms(%s))" % (self.method, self.server, self.port, self.uri, self.freq)

class Mem(Rule):

	def __init__( self, max, freq=Time.m(1), fail=() ):
		Rule.__init__(self, freq, fail)
		self.max = max
		pass

	def run( self ):
		Rule.run(self)
		return True

	def __repr__( self ):
		return "Mem(max=Size.b(%s), freq.Time.ms(%s))" % (self.max, self.freq)

class Action:

	def __init__( self ):
		pass
	
	def run( self, event, service ):
		pass


class Stdout(Action):

	def __init__( self ):
		Action.__init__(self)
	
	def run( self, event, service ):
		print "%s: %s :: %s\n" % (now(), service and service.name, event)
		return True

class Log(Action):

	def __init__( self, path ):
		Action.__init__(self)
		self.path = path
	
	def run( self, event, service ):
		f = file( self.path, 'a')
		f.write("%s: %s :: %s\n" % (now(), service and service.name, event))
		f.flush()
		f.close()
		return True

class Restart(Action):

	def __init__( self, command ):
		self.command = command
	
	def run( self, event, service ):
		#os.popen(self.command)
		return True

class Service:

	def __init__( self, name, cmdline, rules=(), actions={} ):
		self.name    = name
		self.cmdline = cmdline
		self.rules   = []
		self.actions = {}
		map(self.addRule, rules)
		self.actions.update(actions)
	
	def addRule( self, rule ):
		self.rules.append(rule)

	def act( self, name, event ):
		"""Runs the action with the given name."""
		assert self.actions.has_key(name)
		# NOTE: Document the protocol
		Runner(self.actions[name]).run(event, self)

class Runner:
	"""Wraps a Rule or Actionin a speparate thread an invoked the 'onEnded' callback once the
	rule is executed."""

	def __init__( self, runnable, context=None ):
		self.startTime = now()
		assert isinstance(runnable, Action) or isinstance(runnable, Rule)
		self._onRunEnded = None
		self.runnable    = runnable
		self.context     = context
		self.status      = None
		self._thread     = threading.Thread(target=self._run)

	def onRunEnded( self, callback ):
		self._onRunEnded = callback
		return self

	def run( self, *args ):
		self.args = args
		self._thread.start()
		return self

	def _run( self ):
		try:
			self.status  = self.runnable.run(*self.args)
		except Exception, e:
			self.status = e
			# FIXME: Rewrite this properly
			print "Exception occured in 'run' with:", self.runnable
			print "-->", e
		self.endTime = now()
		if self._onRunEnded: self._onRunEnded(self)

class Monitor:

	FREQUENCY = Time.s(20)

	def __init__( self, *services ):
		self.services  = []
		self.isRunning = False
		self.freq      = self.FREQUENCY
		self.logger    = Logger()
		map(self.addService, services)
	
	def addService( self, service ):
		self.services.append(service)
	
	def run( self ):
		self.isRunning = True
		while self.isRunning:
			next_run = now() + self.freq
			self.logger.info("Checking services: ", ", ".join(s.name for s in self.services))
			for service in self.services:
				for rule in service.rules:
					to_wait = rule.shouldRunIn()
					if to_wait > 0:
						next_run = min(now() + to_wait, next_run)
					else:
						# FIXME: Should go through a rule runner
						Runner(rule,context=service).onRunEnded(self.onRuleEnded).run()
			# Sleeps waiting for the next run
			sleep_time = max(0, next_run - now())
			if sleep_time > 0:
				self.logger.info("Sleeping for %0.2fs" % (sleep_time / 1000.0))
				time.sleep(sleep_time / 1000.0)
				self.logger.sep()

	def onRuleEnded( self, runner ):
		# FIXME: Handle exception
		rule    = runner.runnable
		service = runner.context
		if runner.status is False:
			self.logger.err("Failure on ", rule)
			if rule.fail:
				self.logger.info("Triggering:", ", ".join(rule.fail))
			else:
				self.logger.info("No failure action to trigger")
			for action in rule.fail:
				# NOTE: Document the protocol
				service.act(action, rule)

if __name__ == "__main__":

	registerSignals()
	Monitor(
		Service(
			# STEP 1: You describe the service
			name    = "bidserver",
			cmdline = "-jar /opt/services/adkit/adkit-bidserver.jar",
			# STEP 2: You specify rules
			rules   = (
				HTTP(GET="bd-1.weservemanyads.com:9030/api/ping", freq=Time.ms(1000), fail=["restart", "log"]),
				Mem (max=Size.MB(1200), freq=Time.ms(1000),                           fail=["restart", "log"]),
			),
			# STEP 2: You specify actions
			actions = dict(
				log     = Log     (path="bidserver.log"),
				notify  = Stdout  (),
				restart = Restart (command="supervisorctl restart adkit-bidserver")
			)
		),
		Service(
			name    = "pamela-web",
			cmdline = "pamela-web",
			rules   = (
				HTTP(GET="localhost:8000/", freq=Time.ms(1000)),
				Mem (max=Size.MB(1200), freq=Time.ms(1000)),
			)
		)
	).run()

# EOF
