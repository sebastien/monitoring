from monitoring import Time, Rule, Success, Failure

try:
	from jenkinsapi.jenkins import Jenkins as JenkinsApi
except ImportError:
	JenkinsApi = None

class Jenkins(Rule):

	def __init__(self, server='localhost:8080', user=None, passw=None,
							 monitor_queue=None, freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.server = server
		self.action = None
		if monitor_queue:
			self.action = 'monitor_queue:%s' % monitor_queue
		self.jenkins = JenkinsApi(server, user, passw) if JenkinsApi else None

	def run(self):
		Rule.run(self)
		assert self.jenkins, "jenkinsapi module is not  installed"
		if self.action == 'monitor_queue:global':
			try:
				return Success(len(self.jenkins.get_queue().keys()))
			except Exception as e:
				return Failure("Error connecting to jenkins. %s" % e)
		else:
			raise Exception("Unknown action {action}".format(action=self.action))

	def __repr__(self):
		return "Jenkins({action}, {server})".format(action=self.action, server=self.server)

# EOF - vim: ts=4 noet
