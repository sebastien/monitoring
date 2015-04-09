#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Monitoring
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   29-Dec-2014
# Last mod.         :   09-Apr-2015
# -----------------------------------------------------------------------------

import os, time, sys, copy
from   monitoring import Tmux

# -----------------------------------------------------------------------------
#
# SERVICE
#
# -----------------------------------------------------------------------------

class Service(object):
	"""A minimal class to implement services that support start/stop/status
	directives."""

	Instance      = None
	CONFIGURATION = {}

	@classmethod
	def Ensure( cls ):
		if not cls.Instance: cls.Instance = cls()
		return cls.Instance

	@classmethod
	def Run( cls, *args ):
		if not args or len(args) == 0: args = sys.argv[1:]
		d         = cls.Ensure()
		args      = args or ["start"]
		directive = args[0]
		args      = args[1:]
		lines     = d.lines
		if hasattr(d, directive):
			result = getattr(d, directive)(*args)
			# If the directive did not output anything, we print its output
			if d.lines == lines:
				d.out("{0}: {1}".format(directive, d.format(result)))
		else:
			raise Exception("Directive not found in daemon {1}: {0}".  format(directive, d))

	def __init__( self, config=None ):
		"""Initializes the service with the given `config`uration, which
		can be a path (string) or a dictionary of values"""
		self.lines = 0
		if not config:
			config_path = self.__class__.__name__.rsplit(".", 1)[-1].lower() + ".json"
			if os.path.exists(config_path):
				with open(config_path) as f:
					config = json.load(f)
			else:
				config = copy.deepcopy(self.CONFIGURATION)
		elif isinstance(config, str):
			with open(config_path) as f:
				config = json.load(f)
		self.config = config

	def out( self, *args ):
		for a in args:
			sys.stdout.write(str(a))
		sys.stdout.write("\n")
		self.lines += 1
		return self

	def format( self, value ):
		return value

	def start( self ):
		pass

	def stop( self ):
		pass

	def status( self ):
		pass

	def restart( self ):
		self.stop()
		self.start()

# -----------------------------------------------------------------------------
#
# TMUX SERVICE
#
# -----------------------------------------------------------------------------

class TmuxService(Service):
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

# EOF - vim: tw=80 ts=4 sw=4 noet
