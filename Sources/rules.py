# -----------------------------------------------------------------------------
#
# RULES
#
# -----------------------------------------------------------------------------

class Rule:
	"""Rules return either a Sucess or Failure when run, and take actions
	as 'fail' or 'success' arguments, which will be triggered by the
	monitoring service."""

	COUNT = 0

	def __init__(self, freq, fail=(), success=()):
		self.id = Rule.COUNT
		# Ensures that the given data is given as a list
		if not (type(fail) in (tuple, list)):
			fail = tuple([fail])
		if not (type(success) in (tuple, list)):
			success = tuple([success])
		Rule.COUNT  += 1
		self.lastRun = 0
		self.name    = None
		self.freq    = freq
		self.fail    = fail
		self.success = success

	def shouldRunIn(self):
		if self.lastRun == 0:
			return 0
		else:
			since_last_run = now() - self.lastRun
			return self.freq - since_last_run

	def touch(self):
		self.lastRun = now()

	def run(self):
		self.touch()
		return Success()

	def __str__( self ):
		if self.name:
			return "<%s@%s %s>"% (self.__class__.__name__, self.name, self.id)
		else:
			return "<%s %s>" % (self.__class__.__name__, self.id)


class HTTP(Rule):

	def __init__(self, GET=None, POST=None, HEAD=None, timeout=Time.s(10), freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		url = None
		#method = None
		if GET:
			method = "GET"
			url = GET
		elif POST:
			method = "GET"
			url = POST
		elif HEAD:
			method = "HEAD"
			url = HEAD

		if url.startswith("http://"):
			url = url[7:]
		server, uri = url.split("/",  1)
		if not uri.startswith("/"):
			uri = "/" + uri
		if server.find(":") >= 0:
			server, port = server.split(":", 1)
		else:
			port = 80
		self.server = server
		self.port = port
		self.uri = uri
		self.body = ""
		self.headers = None
		self.method = method
		self.timeout = timeout / 1000.0

	def run(self):
		Rule.run(self)
		conn = httplib.HTTPConnection(self.server, self.port, timeout=self.timeout)
		res = None
		try:
			conn.request(self.method, self.uri, self.body, self.headers or {})
			resp = conn.getresponse()
			res = resp.read()
		except socket.error, e:
			return Failure("Socket error: %s" % (e))
		if resp.status >= 400:
			return Failure("HTTP response has error status %s" % (resp.status))
		else:
			return Success(res)

	def __repr__(self):
		return "HTTP(%s=\"%s:%s%s\",timeout=%s)" % (self.method, self.server, self.port, self.uri, self.timeout)


class SystemHealth(Rule):
	"""Defines thresholds for key system health stats."""

	def __init__(self, freq=Time.s(1), cpu=0.90, disk=0.90, mem=0.90, fail=(), success=()):
		"""Monitors the system health with the following thresholds:

		- 'cpu'  (0.90 by default)
		- 'disk' (0.90 by default)
		- 'mem'  (0.90 by default)

		"""
		Rule.__init__(self, freq, fail, success)
		self.cpu = cpu
		self.disk = disk
		self.mem = mem

	def run(self):
		"""Checks wether the collected stats are within the threshold or not. In
		case of failure, the failure data will be like a list of these:

		- ['cpu' , <actual value:float>, <threshold value:float>]
		- ['mem' , <actual value:float>, <threshold value:float>]
		- ['disk', <actual value:float>, <threshold value:float>, <mount point:string>]

		"""
		errors = {}
		values  = {}
		cpu  = System.CPUUsage()
		mem  = System.MemoryUsage()
		disk = System.DiskUsage()
		if cpu > self.cpu:
			errors["cpu"] = (cpu, self.cpu)
		else:
			values["cpu"] = (cpu, self.cpu)
		if mem > self.mem:
			errors["cpu"] = (mem, self.mem)
		else:
			values["mem"] = (mem, self.mem)
		for mount, usage in disk.items():
			if usage > self.disk:
				errors.setdefault("disk", {})
				errors["disk"][mount] = (usage, self.disk)
			else:
				values.setdefault("disk", {})
				values["disk"][mount] = (usage, self,disk)
		if errors:
			return Failure("errors with %s" % (", ".join(errors.keys())), value=dict(values=values, errors=errors))
		else:
			return Success(value=dict(values=values))

class ProcessInfo(Rule):
	"""Returns statistics about the process with the given command, the rule
	returns the same value as 'Process.Info'."""

	def __init__(self, command, freq, fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.command = command

	def run(self):
		pid = Process.GetWith(self.command)
		if pid:
			pid = pid[0]
			info = Process.Info(pid)
			if info["exists"]:
				return Success(info)
			else:
				return Failure("Process %s does not exists anymore" % (pid))
		else:
			return Failure("Cannot find process with command like: %s" % (self.command))


class SystemInfo(Rule):

	def __init__(self, freq, fail=(), success=()):
		Rule.__init__(self, freq, fail, success)

	def run(self):
		return Success(dict(
			memoryUsage=System.MemoryUsage(),
			diskUsage=System.DiskUsage(),
			cpuUsage=System.CPUUsage(),
		))


class Bandwidth(Rule):
	"""Measure the bandwiths for the system"""

	def __init__(self, interface, freq, fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.interface = interface

	def run(self):
		res = System.GetInterfaceStats()
		if res.get(self.interface):
			return Success(res[self.interface])
		else:
			return Failure("Cannot find data for interface: %s" % (self.interface))


class Mem(Rule):

	def __init__(self, max, freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.max = max
		pass

	def run(self):
		Rule.run(self)
		return Success()

	def __repr__(self):
		return "Mem(max=Size.b(%s), freq.Time.ms(%s))" % (self.max, self.freq)


class Delta(Rule):
	"""Executes a rule and extracts a numerical value out of it, successfully returning
	when at least two values have been extracted from the given rule."""

	def __init__(self, rule, extract=lambda res: res, fail=(), success=()):
		Rule.__init__(self, rule.freq, fail, success)
		self.extractor = extract
		self.rule = rule
		self.previous = None

	def run(self):
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


class Succeed(Rule):

	def __init__(self, freq, actions=()):
		Rule.__init__(self, freq, fail=(), success=actions)

	def run(self):
		return Success()


class Always(Succeed):

	def __init__(self, freq, actions=()):
		Succeed.__init__(self, freq, actions)


class Fail(Rule):

	def __init__(self, freq, actions=()):
		Rule.__init__(self, freq, fail=actions, success=())

	def run(self):
		return Failure()

