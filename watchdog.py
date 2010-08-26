#!/usr/bin/env python

import os, time, httplib, socket, threading

def cat( path ):
	f = file(path, 'rb')
	d = f.read()
	f.close()
	return d

def count( path ):
	return len(os.path.listdir(path))

def now():
	return time.time() * 1000

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

	def __init__( self, freq ):
		self.lastRun = 0
		self.freq    = freq
	
	def shouldRunIn( self ):
		return self.freq - (now() - self.lastRun)

	def run( self ):
		self.lastRun = now()
		return True

class HTTP(Rule):

	def __init__( self, GET=None, POST=None, timeout=Time.s(10), freq=Time.m(1)):
		Rule.__init__(self, freq)
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

	def __init__( self, max, freq=Time.m(1) ):
		Rule.__init__(self, freq)
		self.max = max
		pass

	def run( self ):
		Rule.run(self)
		return True

	def __repr__( self ):
		return "Mem(max=Size.b(%s), freq.Time.ms(%s))" % (self.max, self.freq)

class Action:

	def __init__( self ):


class Stdout(Action):

	def __init__( self, path ):
		self
	
	def run( self, event=None, service=None ):
		print "%s: %s :: %s\n" % (now(), service and service.name, event)
		return True

class Log(Action):

	def __init__( self, path ):
		self
	
	def run( self, event=None, service=None ):
		f = file(path, 'o')
		o.write("%s: %s :: %s\n" % (now(), service and service.name, event))
		f.flush()
		f.close()
		return True

class Service:

	def __init__( self, name, cmdline, rules=() ):
		self.rules = []
		map(self.addRule, rules)
	
	def addRule( self, rule ):
		self.rules.append(rule)

class RuleRunner:
	"""Wraps a Rule in a speparate thread an invoked the 'onEnded' callback once the
	rule is executed."""

	def __init__( self, rule, onEnded ):
		self.startTime = now()
		self.onEnded   = onEnded
		self.rule      = rule
		self.status    = None
		self._thread   = threading.Thread(target=self._run)

	def run( self ):
		self._thread.start()

	def _run( self ):
		self.status  = self.rule()
		self.endTime = now()
		self.onEnded(self, self.status)

class Monitor:

	def __init__( self, *services ):
		self.services  = []
		self.isRunning = False
		self.freq      = Time.s(1)
		map(self.addService, services)
	
	def addService( self, service ):
		self.services.append(service)
	
	def run( self ):
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
						print rule, rule.run()
			# Sleeps waiting for the next run
			sleep_time = max(0, next_run - now())
			if sleep_time > 0:
				print "Sleeping for", sleep_time / 1000.0
				time.sleep(sleep_time / 1000.0)

if __name__ == "__main__":

	Monitor(
		Service(
			# STEP 1: You describe the service
			name    = "bidserver",
			cmdline = "-jar /opt/services/adkit/adkit-bidserver.jar",
			# STEP 2: You specify rules
			rules   = (
				HTTP(GET="bd-1.weservemanyads.com:9030/api/ping", freq=Time.ms(1000), fail=["restart", "log", "notify"]),
				Mem (max=Size.MB(1200), freq=Time.ms(1000),                           fail=["restart", "log", "notify"]),
			)
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
