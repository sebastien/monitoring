#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Monitoring
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   29-Dec-2014
# Last mod.         :   29-Dec-2014
# -----------------------------------------------------------------------------

import argparse, time
from   monitoring import Tmux

class TmuxDaemon:
	"""Creates long-running processed running within a dedicated Tmux
	session. This allows to interactively query/manipulate
	processes within a tmux shell."""

	# TODO: Ideally, we would be able to list the PIDs of processes
	# running within a tmux window, and identify which one is the daemon
	# in question.

	@classmethod
	def Has( cls, name ):
		return Tmux.HasSession(name) and Tmux.HasWindow(name, "daemon")

	def __init__( self, name, command=None ):
		self.name    = name
		self.command = command
		assert self.name

	def start( self, command=None ):
		command = command or self.command
		if not self.Has(self.name):
			Tmux.EnsureSession(self.name)
			Tmux.EnsureWindow(self.name, "daemon")
		if Tmux.IsResponsive(self.name, "daemon"):
			if not command: command = Tmux.Run(self.name, "daemon", "echo $DAEMON_COMMAND")
			# We assume that the daemon's will not detach from tmux, so if
			# the shell is not responsive, it means the daemon is running
			Tmux.Write(self.name, "daemon", "export DAEMON_COMMAND=\"{0}\"".format( command.replace('"', '\\"')))
			Tmux.Write(self.name, "daemon", command)
		return True

	def stop( self ):
		if self.Has(self.name):
			# This sends a Ctrl-C.
			Tmux.Write(self.name, "daemon", "C-c")
			# If the window does not become responsive after 5s, we kill the
			# window.
			if not Tmux.IsResponsive(self.name, "daemon", timeout=5):
				Tmux.KillWindow(self.name, "daemon")
			return True
		else:
			return False

	def restart( self ):
		self.stop()
		self.start()

def run( daemon, directive, *args ):
	d = TmuxDaemon(daemon)
	if hasattr(d, directive):
		getattr(d, directive)(*args)
	else:
		raise Exception("Directive not found: {0}". format(directive))

if __name__ == "__main__":
	import sys
	args = sys.argv[1:]
	run(*args)

# EOF - vim: tw=80 ts=4 sw=4 noet
