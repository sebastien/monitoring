# -----------------------------------------------------------------------------
#
# ACTIONS
#
# -----------------------------------------------------------------------------

class Action:
	"""Represents actions that can be triggered on rule sucess or failure."""

	COUNT = 0

	def __init__(self):
		self.name  = None
		self.id    = self.COUNT
		self.COUNT += 1

	def info( self, *message ):
		Logger.I().info(*message)
	
	def err( self, *message ):
		Logger.I().err(*message)

	def debug( self, *message ):
		Logger.I().debug(*message)

	def warn( self, *message ):
		Logger.I().warn(*message)

	def run(self, monitor, service, rule, runner):
		pass

	def __str__( self ):
		if self.name:
			return "<%s@%s %s>"% (self.__class__.__name__, self.name, self.id)
		else:
			return "<%s %s>" % (self.__class__.__name__, self.id)

class Log(Action):
	"""Logs results to the given path."""

	def __init__(self, path=None, stdout=True, overwrite=False):
		Action.__init__(self)
		self.path = path
		self.stdout = stdout
		self.overwrite = overwrite

	def preamble(self, monitor, service, rule, runner):
		return "%s %s[%d]" % (timestamp(), service and service.name, runner.iteration)

	def successMessage(self, monitor, service, rule, runner):
		return "%s --- %s succeeded (in %0.2fms)" % (self.preamble(monitor, service, rule, runner), runner.runable, runner.duration)

	def failureMessage(self, monitor, service, rule, runner):
		return "%s [!] %s of %s (in %0.2fms)" % (self.preamble(monitor, service, rule, runner), runner.result, runner.runable, runner.duration)

	def run(self, monitor, service, rule, runner):
		if runner.hasFailed():
			msg = self.failureMessage(monitor, service, rule, runner) + "\n"
		else:
			msg = self.successMessage(monitor, service, rule, runner) + "\n"
		self.log(msg)

	def log(self, message):
		if self.stdout:
			sys.stdout.write(message)
		if self.path:
			f = file(self.path, (self.overwrite and 'w') or 'a')
			f.write(message)
			f.flush()
			f.close()
		return True

	def __call__(self, message):
		self.log(message)


class Print(Log):

	def __init__(self, message, path=None, stdout=True, overwrite=False):
		Log.__init__(self, path, stdout, overwrite)
		self.message = message

	def run(self, monitor, service, rule, runner):
		self.log(self.message + "\n")


class LogResult(Log):

	def __init__(self, message, path=None, stdout=True, extract=lambda r, _: r, overwrite=False):
		Log.__init__(self, path, stdout, overwrite)
		self.message = message
		self.extractor = extract

	def successMessage(self, monitor, service, rule, runner):
		return "%s %s %s" % (self.preamble(monitor, service, rule, runner), self.message, self.extractor(runner.result.value, runner))


class LogMonitoringStatus(Log):

	def __init__(self, path=None, stdout=True, overwrite=False):
		Log.__init__(self, path, stdout, overwrite)

	def successMessage(self, monitor, service, rule, runner):
		return "%s %s" % (self.preamble(monitor, service, rule, runner), monitor.getStatusMessage())

class Run(Action):

	def __init__(self, command, cwd=None, detach=False):
		Action.__init__(self)
		self.command = command
		self.cwd = cwd
		self.detach = detach

	def run(self, monitor, service, rule, runner):
		res = popen(self.command, self.cwd, check=True, detach=self.detach)
		if type(res) == tuple:
			Logger.Err("Run:", self.command, " failed with ", repr(res[1]))
			return False
		else:
			Logger.Output("Run:", self.command, ":", res)
			return True

class TmuxRun(Action):
	"""An action that executes the given command in a tmux window with
	the given name and session."""

	def __init__( self, session, window, command, cwd="." ):
		Action.__init__(self)
		self.session = session
		self.window  = window
		self.command = command
		self.cwd     = cwd
		self.tmux    = Tmux
	
	def run(self, monitor, service, rule, runner):
		self.tmux.EnsureSession(self.session)
		self.tmux.EnsureWindow (self.session, self.window)
		# Is the terminal responsive?
		key = "TMUX_ACTION_CHECK_{0}".format(time.time())
		self.tmux.Write(self.session, self.window, "echo " + key)
		# We check if the terminal is responsive. If not we let it 1s to 
		# process the command before killing the window
		is_responsive = False
		for i in range(10):
			text = self.tmux.Read(self.session, self.window)
			is_responsive = text.find(key) != -1
			if not is_responsive:
				time.sleep(0.1)
			else:
				break
		# If the terminal is not responsive, we simply kill then window
		# and restart it
		if not is_responsive:
			self.tmux.KillWindow(self.session, self.window)
			self.tmux.EnsureWindow(self.session, self.window)
		# We're now safe to start the command
		self.tmux.Write(self.session, self.window, "cd {0} ; {1}".format(self.cwd, self.command))

class Restart(Action):
	"""Restarts the process with the given command, killing the process if it
	already exists, starting it if it doesn't. Use this one with care as the
	process will become a child of the monitoring -- it's better to use
	start/stop scripts if the process is long-running."""

	def __init__(self, command, cwd=None):
		Action.__init__(self)
		self.command = command
		self.cwd = cwd

	def run(self, monitor, service, rule, runner):
		process_info = Process.Find(self.command)
		if not process_info:
			Process.Start(self.command, cwd=self.cwd)
		else:
			pid, ppid, cmd = process_info
			Process.Kill(pid=pid)
			Process.Start(cmd, cwd=self.cwd)
		return True


class Email(Action):
	"""Sends an email"""

	MESSAGE = """\
	|From: ${from}
	|To:   ${to}
	|Subject: ${subject}
	|
	|${message}
	|--
	|Timestamp: ${timestamp}
	|Iteration: ${iteration}
	|Result:    ${result}
	|--
	""".replace("\t|", "")

	def __init__(self, recipient, subject, message, host, user=None, password=None, origin=None):
		Action.__init__(self)
		self.recipient = recipient
		self.subject = subject
		self.message = message
		self.host = host
		self.user = user
		self.password = password
		self.origin = origin

	def run(self, monitor, service, rule, runner):
		if self.send(monitor, service, rule, runner):
			Logger.Info("Email sent to %s (#%s)" % (self.recipient, monitor.iteration))
		else:
			Logger.Err("Could not send email to %s (#%s)" % (self.recipient, monitor.iteration))
	def send(self, monitor=None, service=None, rule=None, runner=None):
		server = smtplib.SMTP(self.host)
		origin = self.origin or "<Monitoring for %s> monitoring@%s" % (service and service.name, popen("hostname")[:-1])
		message = string.Template(self.MESSAGE).safe_substitute({
			"from": origin,
			"to": self.recipient,
			"subject": self.subject,
			"message": self.message,
			"result": runner and runner.result,
			"timestamp": timestamp(),
			"iteration": monitor and monitor.iteration or 0
		})
		server.ehlo()
		server.starttls()
		server.ehlo()
		if self.password:
			server.login(self.user, self.password)
		server.sendmail(origin, self.recipient, message)
		try:
			server.quit()
		except:
			pass
		return message


class XMPP(Action):
	"""Sends an XMPP message"""

	def __init__(self, recipient, message, user=None, password=None):
		Action.__init__(self)
		# FIXME: Add import error, suggest to easy_install pyxmpp
		try:
			import xmpp
		except ImportError, e:
			raise Exception("Package `pyxmpp` is required: easy_install pyxmpp")
		self.xmpp = xmpp
		self.recipient = recipient
		self.message = message
		self.user = user
		self.password = password

	def run(self, monitor, service, rule, runner):
		if self.send(monitor, service, rule, runner):
			Logger.Info("XMPP message sent to %s (#%s)" % (self.recipient, monitor.iteration))
		else:
			Logger.Err("Could not send XMPP message to %s (#%s)" % (self.recipient, monitor.iteration))

	def send(self, monitor=None, service=None, rule=None, runner=None):
		jid = self.xmpp.protocol.JID(self.user)
		client = self.xmpp.Client(jid.getDomain(), debug=([]))
		conn = client.connect()
		if not conn:
			Logger.Err("Cannot connect to XMPP account (name=%s)" % (self.user))
			return False
		auth = client.auth(jid.getNode(), self.password, resource=(jid.getResource()))
		if not auth:
			Logger.Err("Cannot authenticate to XMPP account (name=%s)" % (self.user))
			return False
		message = string.Template(self.message).safe_substitute({
			"to": self.recipient,
			"service": service and service.name,
			"result": runner and runner.result,
			"timestamp": timestamp(),
			"iteration": monitor and monitor.iteration or 0
		})
		try:
			client.send(self.xmpp.protocol.Message(self.recipient, message))
			client.disconnect()
		except Exception, e:
			Logger.Err("Cannot send XMPP message: " + str(e))
		return True


class Incident(Action):
	"""Triggers an action if there are N errors (5 by default) within a time
	lapse T (in ms, 30,000 by default)."""

	def __init__(self, actions, errors=5, during=30 * 1000):
		Action.__init__(self)
		if not (type(actions) in (tuple, list)):
			actions = tuple([actions])
		self.actions = actions
		self.errors = errors
		self.during = during
		self.errorValues = []
		self.errorStartTime = 0

	def run(self, monitor, service, rule, runner):
		"""When the number of errors is reached within the period, the given
		actions are triggered."""
		if not self.errorValues:
			self.errorStartTime = now()
		elapsed_time = now() - self.errorStartTime
		self.errorValues.append(runner.result)
		if len(self.errorValues) >= self.errors and elapsed_time >= self.during:
			self.errorValues = []
			for action in self.actions:
				# FIXME: Should clone the runner and return the result
				action.run(monitor, service, rule, runner)


class ZMQPublish(Action):
	"""Publishes a value through ZeroMQ, making it available for other ZeroMQ
	clients to subscribe"""

	ZMQ_CONTEXT = None
	ZMQ_SOCKETS = {}

	@classmethod
	def getZMQContext(cls):
		import zmq
		if cls.ZMQ_CONTEXT is None:
			cls.ZMQ_CONTEXT = zmq.Context()
		return cls.ZMQ_CONTEXT

	@classmethod
	def getZMQSocket(cls, url):
		if url not in cls.ZMQ_SOCKETS.keys():
			import zmq
			cls.ZMQ_SOCKETS[url] = cls.getZMQContext().socket(zmq.PUB)
			cls.ZMQ_SOCKETS[url].bind(url)
		return cls.ZMQ_SOCKETS[url]

	def __init__(self, variableName, host="0.0.0.0", port=9009, extract=lambda r, _: r):
		Action.__init__(self)
		self.host = host
		self.port = port
		self.name = variableName
		self.url = "tcp://%s:%s" % (self.host, self.port)
		self.extractor = extract
		self.socket = ZMQPublish.getZMQSocket(self.url)

	def send(self, runner):
		# FIXME: I think this is a blocking operation
		message = "%s:application/json:%s" % (self.name, json.dumps(self.extractor(runner.result.value, runner)))
		# NOTE: ZMQ PUB is asynchronous, ZMQ DOWNSTREAM is not !
		self.socket.send(message)
		return message

	def run(self, monitor, service, rule, runner):
		self.send(runner)
