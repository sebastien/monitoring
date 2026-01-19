from monitoring import Action
import librato

# pip install librato-metrics


class Librato(Action):
	"""Sends the result to librato metrics"""

	def __init__(self, name, user=None, token=None, source=None, extract=lambda r, _: r):
		Action.__init__(self)
		self.extract = extract
		self.name = name
		self.source = source
		self.librato_api = librato.connect(user, token)

	def run(self, monitor, service, rule, runner):
		if not runner.hasFailed():
			value = self.extract(runner.result.value, runner)
			self.send(value)

	def send(self, value):
		self.librato_api.submit(self.name, value, source=self.source)
		return True

	def __call__(self, value):
		self.send(value)

# EOF - vim: ts=4 noet
