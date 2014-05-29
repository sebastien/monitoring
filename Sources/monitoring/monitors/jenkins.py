from monitoring import Time, Rule, Success
from jenkinsapi.jenkins import Jenkins as JenkinsApi


class Jenkins(Rule):
  def __init__(self, server='localhost:8080', user=None, passw=None,
               monitor_queue=None, freq=Time.m(1), fail=(), success=()):
    Rule.__init__(self, freq, fail, success)
    self.server = server
    self.action = None
    if monitor_queue:
      self.action = 'monitor_queue:%s' % monitor_queue
    self.jenkins = JenkinsApi(server, user, passw)

  def run(self):
    Rule.run(self)
    if self.action == 'monitor_queue:global':
      return Success(len(self.jenkins.get_queue().keys()))
    else:
      raise Exception("Unknown action {action}".format(action=self.action))

  def __repr__(self):
    return "Jenkins({action}, {server})".format(action=self.action, server=self.server)
