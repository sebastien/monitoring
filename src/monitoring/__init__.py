#!/usr/bin/env python
# -----------------------------------------------------------------------------
# Project           :   Monitoring
# -----------------------------------------------------------------------------
# Author            :   Sebastien Pierre                  <sebastien@ffctn.com>
# License           :   Revised BSD Licensed
# -----------------------------------------------------------------------------
# Creation date     :   10-Feb-2010
# Last mod.         :   09-Apr-2015
# -----------------------------------------------------------------------------

from __future__ import print_function

import re, sys, os, time, datetime, stat, smtplib, string, json, fnmatch, types
import socket, threading, subprocess, glob, traceback
try:
	import httplib
except ImportError as e:
	import http as httplib

# TODO: Add System health metrics (CPU%, MEM%, DISK%, I/O, INODES)

# FIXME: HTTP should use httplib2, pool HTTP requests (and limit to a maximum),
# should also force close after a certain time (cappedpool)

# FIXME: Prevent flooding of taskrunner, ie. when tasks take longer than
# their duration, this is valid for actions or rules taking too long.

# FIXME: One of the scenario is that the frequency of an action is shorter than
# the execution time, so that you have an accumulation

# FIXME: Ensure re-ordering of logging

#  File "sample-reporter.py", line 35, in <module>
#    fail    = [SendStat(ADKIT_STATSERVICE, "mediaserver.ms-1.failure")]
#  File "/home/sebastien/Projects/Local/lib/python/monitoring.py", line 669, in run
#    Runner(rule,context=service,iteration=self.iteration).onRunEnded(self.onRuleEnded).run()
#  File "/home/sebastien/Projects/Local/lib/python/monitoring.py", line 620, in run
#    self._thread.start()
#  File "/usr/lib/python2.6/threading.py", line 474, in start
#    _start_new_thread(self.__bootstrap, ())
#thread.error: can't start new thread

__version__ = "0.9.11"

RE_SPACES  = re.compile("\s+")
RE_INTEGER = re.compile("\d+")

def config(variable, default, normalize=lambda _:_):
	return normalize(os.environ.get(variable.upper().replace(".","_")) or default)

def cat(path,default=""):
	"""Outputs the content of the file at the given path"""
	try:
		with open(path, 'r') as f:
			d = f.read()
	except Exception as e:
		d = default
	return d

def count(path):
	"""Count the number of files and directories at the given path"""
	try:
		return len(os.listdir(path))
	except Exception as e:
		# We most probably hit a permission denied here
		return -1

def now():
	"""Returns the current time in milliseconds"""
	return time.time() * 1000

def spawn(cmd, cwd=None):
	"""Spawn a completely detached subprocess (i.e., a daemon).
	"""
	# FROM: http://stackoverflow.com/questions/972362/spawning-process-from-python
	# fork the first time (to make a non-session-leader child process)
	try:
		pid = os.fork()
	except OSError as e:
		raise RuntimeError("1st fork failed: %s [%d]" % (e.strerror, e.errno))
	if pid != 0:
		# parent (calling) process is all done
		return pid
	# detach from controlling terminal (to make child a session-leader)
	os.setsid()
	try:
		pid = os.fork()
	except OSError as e:
		raise RuntimeError("2nd fork failed: %s [%d]" % (e.strerror, e.errno))
	if pid != 0:
		# child process is all done
		os._exit(0)
	# grandchild process now non-session-leader, detached from parent
	# grandchild process must now close all open files
	try:
		maxfd = os.sysconf("SC_OPEN_MAX")
	except (AttributeError, ValueError):
		maxfd = 1024
	for fd in range(maxfd):
		try:
			os.close(fd)
		except OSError: # ERROR, fd wasn't open to begin with (ignored)
			pass
	# redirect stdin, stdout and stderr to /dev/null
	if (hasattr(os, "devnull")):
		REDIRECT_TO = os.devnull
	else:
		REDIRECT_TO = "/dev/null"
	os.open(REDIRECT_TO, os.O_RDWR) # standard input (0)
	os.dup2(0, 1)
	os.dup2(0, 2)
	# and finally let's execute the executable for the daemon!
	try:
		args = filter(lambda _:_, map(lambda _:_.strip(), cmd.split(" ")))
		path_to_executable = args[0]
		args = args[1:]
		os.execv(path_to_executable, args)
	except Exception as e:
		# oops, we're cut off from the world, let's just give up
		os._exit(255)

def popen(command, cwd=None, check=False, detach=False):
	"""Returns the stdout from the given command, using the subproces
	command."""
	if detach:
		return spawn(command, cwd)
	else:
		cmd      = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
		status   = cmd.wait()
		res, err = cmd.communicate()
		if status == 0:
			return res.decode("utf8")
		else:
			return (status, err.decode("utf8"))

def timestamp():
	"""Returns the current timestamp as an ISO-8601 time
	("1977-04-22T01:00:00-05:00")"""
	n = datetime.datetime.now()
	return "%04d-%02d-%02dT%02d:%02d:%02d" % (
		n.year, n.month, n.day, n.hour, n.minute, n.second
	)

def timenum():
	"""Like timestamp, but just the numbers."""
	n = datetime.datetime.now()
	return "%04d%02d%02d%02d%02d%02d" % (
		n.year, n.month, n.day, n.hour, n.minute, n.second
	)


# -----------------------------------------------------------------------------
#
# SIGNAL HANDLING
#
# -----------------------------------------------------------------------------

class Signals:
	"""Takes care of registering/unregistering signals so that shutdown
	(on Ctrl-C) works properly."""

	SINGLETON = None

	@classmethod
	def Setup(cls):
		"""Sets up the shutdown signal handlers."""
		if cls.SINGLETON is None:
			cls.SINGLETON = Signals()
		cls.SINGLETON.setup()

	@classmethod
	def OnShutdown(cls, callback):
		"""Registers a new callback to be triggered on
		SIGINT/SIGHUP/SIGABRT/SIQUITE/SIGTERM."""
		if cls.SINGLETON is None:
			cls.SINGLETON = Signals()
		assert not cls.SINGLETON.signalsRegistered, "OnShutdown must be called before Setup."
		cls.SINGLETON.onShutdown.append(callback)

	def __init__(self):
		self.signalsRegistered = []
		self.onShutdown = []
		try:
			import signal
			self.hasSignalModule = True
		except:
			self.hasSignalModule = False

	def setup(self):
		"""Sets up the signals, registering the shutdown function. You only
		need to call this function once."""
		if self.hasSignalModule and not self.signalsRegistered:
			# Jython does not support all signals, so we only use
			# the available ones
			signals = ['SIGINT',  'SIGHUP', 'SIGABRT', 'SIGQUIT', 'SIGTERM']
			import signal
			for sig in signals:
				try:
					signal.signal(getattr(signal, sig), self._shutdown)
					self.signalsRegistered.append(sig)
				except Exception as e:
					Logger.Err("[!] monitoring.Signals._registerSignals:%s %s\n" % (sig, e))

	def _shutdown(self, *args):
		"""Safely executes the callbacks registered in self.onShutdown."""
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
	def I(cls):
		if cls.SINGLETON is None:
			cls.SINGLETON = Logger()
		return cls.SINGLETON

	@classmethod
	def Err(cls, *message):
		cls.I().err(*message)

	@classmethod
	def Warn(cls, *message):
		cls.I().warn(*message)

	@classmethod
	def Info(cls, *message):
		cls.I().info(*message)

	@classmethod
	def Debug(cls, *message):
		cls.I().debug(*message)

	@classmethod
	def Sep(cls):
		cls.I().sep()

	@classmethod
	def Traceback(cls):
		cls.I().traceback()

	@classmethod
	def Output(cls, *message):
		cls.I().output(*message)

	def __init__(self, stream=sys.stdout, prefix=""):
		self.stream = stream
		self.lock = threading.RLock()
		self.prefix = prefix

	def err(self, *message):
		self("[!]", *message)

	def warn(self, *message):
		self("[-]", *message)

	def info(self, *message):
		self("---", *message)

	def debug(self, *message):
		self("   ", *message)

	def traceback( self ):
		exception = traceback.format_exc()
		lines     = exception.split("\n")[:-1]
		for i in range(len(lines)):
			if i == len(lines) - 1:
				self.err(lines[i])
			else:
				self.debug(lines[i])

	def output(self, *message):
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

	def sep(self):
		self.lock.acquire()
		self.stream.write("\n")
		self.stream.flush()
		self.lock.release()

	def __call__(self, prefix, *message):
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
	"""A collection of utilities to manipulate and interact with running
	processes."""
	# See <http://linux.die.net/man/5/proc>

	RE_PID       = re.compile("^\d+$")
	RE_PS_OUTPUT = re.compile("^%s$" % ("\s+".join([
		"[^.]+",  "(\d+)", "(\d+)", "\d+", "\d+", "\d+", "\d+", "[^ ]+", "[^ ]+", "\d\d\:\d\d\:\d\d", "(.+)"
	])))

	@classmethod
	def FindLike( cls, command, strict=True ):
		if strict:
			predicate = lambda a,b: a in b
		else:
			predicate = lambda a,b: a.lower() in b.lower()
		return cls.Find(command, predicate)

	@classmethod
	def Find(cls, command, compare=(lambda a, b: a == b)):
		command = command.replace("\"","").replace("'","")
		# Note: we skip the header and the trailing EOL
		for pid, cmd in cls.List().items():
			if cmd:
				if compare(command, cmd):
					return (pid, None, cmd)
		return None

	@classmethod
	def Children( cls, pid ):
		"""Returns the list of processes that have the given `pid` as `ppid`"""
		res = []
		pid = int(pid)
		for cpid, cmd in cls.List().items():
			ppid = int(cls.Status(cpid)["ppid"])
			if ppid == pid:
				res.append( (cpid, None, cmd))
		return res

	@classmethod
	def List(cls):
		"""Returns a map of pid to cmdline"""
		res = {}
		for p in glob.glob("/proc/*/cmdline"):
			process = p.split("/")[2]
			if cls.RE_PID.match(process):
				res[int(process)] = cat(p).replace("\x00", " ")
		return res

	@classmethod
	def GetWith(cls, expression, compare=(lambda a, b: fnmatch.fnmatch(a, b))):
		"""Returns a list of all processes that contain the expression
		in their command line."""
		res = []
		expression = "*" + expression + "*"
		for pid, cmdline in cls.List().items():
			if compare(cmdline, expression):
				res.append(pid)
		return res

	@classmethod
	def Status(cls, pid):
		res = {}
		pid = int(pid)
		for line in cat("/proc/%d/status" % (pid)).split("\n"):
			if not line:
				continue
			name, value = line.split(":", 1)
			res[name.lower()] = value.strip()
		return res

	@classmethod
	def Start(cls, command, cwd=None):
		# FIXME: Not sure if we need something like & at the end
		command += ""
		Logger.Info("Starting process: " + repr(command))
		popen(command, cwd)

	@classmethod
	def Kill(cls, pid, children=False):
		"""Kills -9 the process with the given pid."""
		if pid is not None:
			if children:
				for cpid, _, cmd in cls.Children(pid):
					# We need to recursively kill the childrens
					cls.Kill(cpid, children=True)
			Logger.Info("Killing process: " + repr(pid))
			return popen("kill -9 %s" % (pid))
		else:
			return None

	@classmethod
	def Info(cls, pid):
		status = Process.Status(pid)
		proc_pid = "/proc/%d" % (pid)
		if not os.path.exists(proc_pid):
			dict(
				pid=pid,
				exists=False,
				probeStart=cls.firstProbe,
				probeEnd=cls.lastProbe
			)
		else:
			status = Process.Status(pid)
			started = os.stat(proc_pid)[stat.ST_MTIME]
			running = time.time() - started
			# FIXME: Add process start time, end time, cpu %
			return dict(
				pid=pid,
				ppid=int(status["ppid"]),
				exists=True,
				f=count("/proc/%d/fd" % (pid)),
				tasks=count("/proc/%d/task" % (pid)),
				threads=int(status["threads"]),
				cmdline=cat("/proc/%d/cmdline" % (pid)),
				fdsize=status["fdsize"],
				vmsize=status["vmsize"],
				started=started,
				running=running
			)


# -----------------------------------------------------------------------------
#
# SYSTEM
#
# -----------------------------------------------------------------------------

class System:
	"""A collection of utilities to interact with system information"""

	LAST_CPU_STAT = None

	@classmethod
	def MemoryInfo(cls):
		"""Returns the content of /proc/meminfo as a dictionary 'key' -> 'value'
		where value is in kB"""
		res = {}
		for line in cat("/proc/meminfo").split("\n")[:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			name, value = line[:2]
			res[name.replace("(", "_").replace(")", "_").replace(":", "")] = int(value)
		return res

	@classmethod
	def MemoryUsage(cls):
		"""Returns the memory usage (between 0.0 and 1.0) on this system, which
		is total memory - free memory - cached memory."""
		meminfo = cls.MemoryInfo()
		return (meminfo["MemTotal"] - meminfo["MemFree"] - meminfo["Cached"]) / float(meminfo["MemTotal"])

	@classmethod
	def DiskUsage(cls):
		"""Returns a dictionary 'device' -> 'percentage' representing the
		usage of each device. A percentage of 1.0 means completely used,
		0.0 means unused."""
		# >> df -iP
		# Sys. de fich.            Inodes   IUtil.  ILib. IUti% Monte sur
		# /dev/sda1             915712  241790  673922   27% /
		# none                  210977     788  210189    1% /dev
		# none                  215028      19  215009    1% /dev/shm
		# none                  215028      71  214957    1% /var/run
		# none                  215028       2  215026    1% /var/lock
		# /dev/sda5            8364032  500833 7863199    6% /home
		# /home/sebastien/.Private 8364032  500833 7863199    6% /home/sebastien
		res = {}
		for line in popen("df -kP").split("\n")[1:-1]:
			line = RE_SPACES.sub(" ", line).strip().split(" ")
			system, inodes, used_inodes, free_inodes, usage, mount = line
			try:
				usage = float(usage[:-1])
			except ValueError:
				usage = 0
			res[mount] = float(usage) / 100.0
		return res

	@classmethod
	def CPUStats(cls):
		"""Returns  CPU stats, that can be used to get the CPUUsage"""
		# From <http://ubuntuforums.org/showthread.php?t=148781>
		time_list = cat("/proc/stat").split("\n")[0].split(" ")[2:6]
		res = map(int, time_list)
		cls.LAST_CPU_STAT = res
		return res

	@classmethod
	def CPUUsage(cls, cpuStat=None):
		if not cpuStat:
			cpuStat = cls.LAST_CPU_STAT
		stat_now = cls.CPUStats()
		res = []
		for i in range(len(cpuStat)):
			res.append(stat_now[i] - cpuStat[i])
		try:
			usage = (100 - (res[len(res) - 1] * 100.00 / sum(res))) / 100.0
		except ZeroDivisionError:
			usage = 0
		return usage

	@classmethod
	def NetStats(cls):
		# $/proc/net$ sudo cat dev
		# Inter-|   Receive                                                |  Transmit
		#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
		#     lo:454586083  954504    0    0    0     0          0         0 454586083  954504    0    0    0     0       0          0
		#   eth0:55735297   85080    0    0    0     0          0         0  5428643   67978    0    0    0     0       0          0
		#   eth1:3300079052153 11645531967    0 8098    0     0          0         0 3409466791555 6131411252    0    0    0     0       0          0
		#  edge0:       0       0    0    0    0     0          0         0     9763      87    0    0    0     0       0          0
		res = {}
		for line in cat("/proc/net/dev").split("\n")[2:-1]:
			interface, stats = RE_SPACES.sub(" ", line).strip().split(":", 1)
			stats = map(long, stats.strip().split(" "))
			rx_bytes, rx_pack, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compr, rx_multicast, \
			tx_bytes, tx_pack, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed = stats
			res[interface] = {
				"rx": dict(
					bytes=rx_bytes,
					packets=rx_pack,
					errors=rx_errs,
					drop=rx_drop
				),
				"tx": dict(
					bytes=tx_bytes,
					packets=tx_pack,
					errors=tx_errs,
					drop=tx_drop
				),
				"total": dict(
					bytes=tx_bytes + rx_bytes,
					packets=tx_pack + rx_pack,
					errors=tx_errs + rx_errs,
					drop=tx_drop + rx_drop
				)
			}
		return res

# -----------------------------------------------------------------------------
#
# TMUX
#
# -----------------------------------------------------------------------------

class Tmux:
	"""A simple wrapper around the `tmux`  terminal multiplexer that allows to
	create sessions and windows and execute arbitrary code in it.

	This is particularly useful if you want to run command on remote servers
	but still want easy access to their detailed output/interact with them."""

	@classmethod
	def Cmd( self, params ):
		cmd = "tmux " + params
		res = popen(cmd)
		if isinstance(res, tuple):
			if res[1].find("failed to connect to server:") != -1:
				# there's not tmux session running so we just return nothing
				return ""
			else:
				raise Exception("Failed running command: {0}, exception: {1}".format(cmd, res))
		else:
			return res

	@classmethod
	def ListSessions( self ):
		return [_ for _ in map(lambda _:_.split(":",1)[0].strip(), self.Cmd("list-session").split("\n")) if _]

	@classmethod
	def EnsureSession( self, session ):
		try:
			sessions = self.ListSessions()
		except:
			sessions = []
		if session not in sessions:
			self.Cmd("new-session -d -s " + session)
		return self

	@classmethod
	def HasSession( self, session ):
		return session in self.ListSessions()

	@classmethod
	def ListWindows( self, session ):
		if not self.HasSession(session): return []
		windows = filter(lambda _:_, self.Cmd("list-windows -t" + session).split("\n"))
		res     = []
		# OUTPUT is like:
		# 1: ONE- (1 panes) [122x45] [layout bffe,122x45,0,0,1] @1
		# 2: ONE* (1 panes) [122x45] [layout bfff,122x45,0,0,2] @2 (active)
		for window in windows:
			index, name = window.split(":",1)
			name        = name.split("(",1)[0].split("[")[0].strip()
			if name[-1] in "*-": name = name[:-1]
			res.append( ( int(index), name, window.endswith("(active)") ))
		return res

	@classmethod
	def GetWindows( self, session, name ):
		if not self.HasSession(session): return []
		return ([_ for _ in self.ListWindows(session) if _[1] == name or _[0] == name])

	@classmethod
	def HasWindow( self, session, name ):
		if not self.HasSession(session): return False
		return self.GetWindows(session, name) and True or False

	@classmethod
	def EnsureWindow( self, session, name ):
		self.EnsureSession(session)
		if not self.GetWindows(session, name):
			self.Cmd("new-window -t {0} -n {1}".format(session, name))
		return self

	@classmethod
	def KillSession( self, session ):
		if not self.HasSession(session): return False
		for i,window,is_active in self.ListWindows(session):
			self.KillWindow(session, window)
		return True

	@classmethod
	def KillWindow( self, session, name ):
		if not self.HasSession(session): return False
		for i,window,is_active in self.GetWindows(session, name):
			self.Cmd("kill-window -t {0}:{1}".format(session, i))
		return True

	@classmethod
	def Read( self, session, name ):
		return self.Cmd("capture-pane -t {0}:{1} \\; save-buffer -".format(session, name))

	@classmethod
	def Write( self, session, name, commands):
		self.Cmd("send-keys -t {0}:{1} {2}".format(session, name, repr(commands)))
		self.Cmd("send-keys -t {0}:{1} C-m".format(session, name))

	@classmethod
	def CtrlC( self, session, name):
		self.Cmd("send-keys -t {0}:{1} C-c".format(session, name))

	@classmethod
	def Run( self, session, name, command, timeout=10, resolution=0.5):
		"""This function allows to run a command and retrieve its output
		as given by the shell. It is quite error prone, as it will include
		your prompt styling and will only poll the output at `resolution` seconds
		interval."""
		self.EnsureWindow(session, name)
		delimiter    = "CMD_" + timenum()
		delimier_cmd = "echo " + delimiter
		output       = None
		found        = False
		self.Write(session, name, command + ";" + delimier_cmd)
		for i in range(int(timeout / resolution)):
			output = self.Read(session, name)
			if ("\n" + delimiter) in output:
				found = True
				break
			else:
				time.sleep(0.1)
		# The command output will be conveniently placed after the `echo
		# CMD_XXX` and before the output `CMD_XXX`. We use negative indexes
		# to avoid access problems when the program's output is too long.
		return output.rsplit(delimiter, 2)[-2].split("\n", 1)[-1] if found else None

	@classmethod
	def IsResponsive( cls, session, window, timeout=1, resolution=0.1 ):
		is_responsive = False
		if cls.HasSession(session) and cls.HasWindow(session, window):
			# Is the terminal responsive?
			key = "TMUX_ACTION_CHECK_{0}".format(time.time())
			cls.Write(session, window, "echo " + key)
			key = "\n" + key
			for i in range(int(timeout / resolution)):
				text = cls.Read(session, window)
				is_responsive = text.find(key) != -1
				if not is_responsive:
					time.sleep(resolution)
				else:
					break
		return is_responsive

# -----------------------------------------------------------------------------
#
# UNITS
#
# -----------------------------------------------------------------------------

class Size:
	"""Converts the given value in the given units to bytes"""

	@classmethod
	def GB(cls, v):
		return cls.MB(v * 1024)

	@classmethod
	def MB(cls, v):
		return cls.KB(v * 1024)

	@classmethod
	def KB(cls, v):
		return cls.B(v * 1024)

	@classmethod
	def B(cls, v):
		return v

class Time:
	"""Converts the given time in the given units to milliseconds"""

	@classmethod
	def w(cls, t):
		return cls.d(7 * t)

	@classmethod
	def d(cls, t):
		return cls.h(24 * t)

	@classmethod
	def h(cls, t):
		return cls.m(60 * t)

	@classmethod
	def m(cls, t):
		return cls.s(60 * t)

	@classmethod
	def s(cls, t):
		return cls.ms(t * 1000)

	@classmethod
	def ms(cls, t):
		return t

# -----------------------------------------------------------------------------
#
# RESULTS ENCAPSULATION
#
# -----------------------------------------------------------------------------

class Result:

	def __init__(self):
		pass

class Success(Result):
	"""Represents the success of a Rule."""

	def __init__(self, value=True, message=None):
		Result.__init__(self)
		self.message = message
		self.value = value
		self.duration = None

	def isSuccess( self ):
		return True

	def isFailure( self ):
		return False

	def __str__(self):
		return str(self.value)

	def __call__(self):
		return self.value


class Failure(Result):
	"""Represents the failure of a Rule."""

	def __init__(self, message="Failure", value=None):
		Result.__init__(self)
		self.message = message
		self.value = value
		self.duration = None

	def isSuccess( self ):
		return False

	def isFailure( self ):
		return True

	def __str__(self):
		return str(self.message)

	def __call__(self):
		return self.value


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

	def __init__(self, message=None, path=None, stdout=True, overwrite=False, rotate=None, limit=None):
		Action.__init__(self)
		self.path      = path
		self.stdout    = stdout
		self.overwrite = overwrite
		self.rotation  = rotate
		self.sizeLimit = limit
		self.message   = message

	def preamble(self, monitor, service, rule, runner):
		return "%s %s[%d]" % (timestamp(), service and service.name, runner.iteration)

	def getMessage( self ):
		message = self.message
		if type(self.message) == types.LambdaType:
			message = message()
		return message

	def successMessage(self, monitor, service, rule, runner):
		return self.getMessage() or "%s --- %s succeeded (in %0.2fms)" % (self.preamble(monitor, service, rule, runner), runner.runable, runner.duration)

	def failureMessage(self, monitor, service, rule, runner):
		return self.getMessage() or "%s [!] %s of %s (in %0.2fms)" % (self.preamble(monitor, service, rule, runner), runner.result, runner.runable, runner.duration)

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
			f = open(self.path, (self.overwrite and 'w') or 'a')
			f.write(message)
			f.flush()
			f.close()
			self.rotate(path)
		return True

	def rotate(self, path):
		limit = self.max or 0
		if os.path.exists(path):
			size = os.stat(path)[stat.ST_SIZE]
			if limit>0 and size > limit:
				# TODO: We should instead rotate or remove data from the
				# log
				os.unlink(path)
				return None
			else:
				return path
		else:
			return None

	def __call__(self, message):
		self.log(message)

class Print(Log):

	def __init__(self, message, path=None, stdout=True, overwrite=False):
		Log.__init__(self, message, path, stdout, overwrite)

	def run(self, monitor, service, rule, runner):
		self.log(self.getMessage() + "\n")

class LogResult(Log):

	def __init__(self, message, path=None, stdout=True, extract=lambda r, _: r, overwrite=False):
		Log.__init__(self, message, path, stdout, overwrite)
		self.extractor = extract

	def successMessage(self, monitor, service, rule, runner):
		return "%s %s %s" % (self.preamble(monitor, service, rule, runner), self.message, self.extractor(runner.result.value, runner))

class LogMonitoringStatus(Log):

	def __init__(self, path=None, stdout=True, overwrite=False):
		Log.__init__(self, None, path, stdout, overwrite)

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

	def run(self, monitor=None, service=None, rule=None, runner=None):
		self.tmux.EnsureSession(self.session)
		self.tmux.EnsureWindow (self.session, self.window)
		if not self.tmux.IsResponsive(self.session, self.window):
			# If the terminal is not responsive, we simply kill then window
			# and restart it
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
		except ImportError as e:
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
		except Exception as e:
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

	def getFrequency( self ):
		return self.freq

	def shouldRunIn(self):
		if self.lastRun == 0:
			return 0
		else:
			since_last_run = now() - self.lastRun
			return self.getFrequency() - since_last_run

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


class CompositeRule( Rule ):

	def __init__(self, rule, freq, fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.rule = rule

	def getFrequency( self ):
		if (self.freq or 0) > 0:
			return self.freq
		elif self.rule:
			return self.rule.getFrequency()
		else:
			return 0

class HTTP(Rule):

	def __init__(self, GET=None, POST=None, HEAD=None, timeout=Time.s(10), freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		url = None
		# TODO: Implement protocol (HTTP/HTTPS)
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
		except socket.error as e:
			return Failure("HTTP request socket error: {method} {server}:{port}{uri} {e}".format(
				method=self.method, server=self.server, port=self.port, uri=self.uri, e=e
			))
		except Exception as e:
			return Failure("HTTP request failed: {method} {server}:{port}{uri} {e}".format(
				method=self.method, server=self.server, port=self.port, uri=self.uri, e=e
			))
		if resp.status >= 400:
			return Failure("HTTP request failed with status {status}: {method} {server}:{port}{uri}".format(
				method=self.method, server=self.server, port=self.port, uri=self.uri, status=resp.status
			))
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
		res = System.NetStats()
		if res.get(self.interface):
			return Success(res[self.interface])
		else:
			return Failure("Cannot find data for interface: %s" % (self.interface))


# TODO
class Mem(Rule):

	def __init__(self, max, freq=Time.m(1), fail=(), success=()):
		Rule.__init__(self, freq, fail, success)
		self.max = max
		pass

	def run(self):
		Rule.run(self)
		return Success()

	def __repr__(self):
		return "Mem(max=Size.b(%s), freq.Time.ms(%s))" % (self.max, self.getFrequency())

class Delta(CompositeRule):
	"""Executes a rule and extracts a numerical value out of it, successfully returning
	when at least two values have been extracted from the given rule."""

	def __init__(self, rule, extract=lambda res: res, freq=None, fail=(), success=()):
		CompositeRule.__init__(self, rule, freq, fail, success)
		self.extractor = extract
		self.rule = rule
		self.previous = None

	def run(self):
		res = self.rule.run()
		if isinstance(res, Success):
			value = self.extractor(res.value)
			if self.previous is None:
				self.previous = value
				return Success(0)
			else:
				delta = value - self.previous
				self.previous = value
				return Success(delta)
		else:
			return res


class Condition( CompositeRule ):

	def __init__(self, rule, test=lambda res: res, freq=None, fail=(), success=()):
		CompositeRule.__init__(self, rule, freq, fail, success)
		self.predicate = test
		self.rule = rule

	def run(self):
		res = self.rule.run()
		if self.predicate(res):
			return Success(res)
		else:
			return Failure(res)

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


# -----------------------------------------------------------------------------
#
# SERVICE
#
# -----------------------------------------------------------------------------

class Service:
	"""A service is a collection of rules and actions. Rules are executed
	and actions are triggered according to the rules result."""

	# FIXME: Add a check() method that checks that actions exists for rules

	def __init__(self, name=None, monitor=(), actions={}, every=None):
		self.name    = name
		self.rules   = []
		self.runners = {}
		self.actions = {}
		self.freq    = None
		if not (type(monitor) in (tuple, list)):
			monitor = tuple([monitor])
		map(self.addRule, monitor)
		self.actions.update(actions)
		self.every(every)

	def getFrequency( self ):
		return self.freq

	def every( self, freq ):
		assert (freq or 0) >= 0, "Freq expected to be >=0, got {0}".format(freq)
		self.freq = freq or 0
		return self

	def addRule(self, rule):
		self.rules.append(rule)

	def getAction(self, nameOrAction):
		"""Returns the action object with the given name."""
		if isinstance(nameOrAction, Action):
			return nameOrAction
		else:
			return self.actions[nameOrAction]

# -----------------------------------------------------------------------------
#
# RUNNER POOL
#
# -----------------------------------------------------------------------------

class Pool:
	"""Pools are used in Monitoring to limit the number of runners/rules executed
	at once. Pools have a maximum capacity, so that you can limit the numbers
	of elements you create."""

	def __init__(self, capacity):
		self.capacity = capacity
		self.elements = []

	def setCapacity( self, capacity ):
		self.capacity = capacity
		return self

	def add(self, element):
		if self.canAdd():
			self.elements.append(element)
			return True
		else:
			return False

	def canAdd(self):
		return len(self.elements) < self.capacity

	def remove(self, element):
		assert element in self.elements
		self.elements.remove(element)

	def size(self):
		return len(self.elements)

# -----------------------------------------------------------------------------
#
# RUNNER
#
# -----------------------------------------------------------------------------

class RunnerStillRunning(Exception):

	def __init__(self, runner):
		Exception.__init__(self, "Runner is still running: " + str(runner))
		self.runner = runner

class RunnerThreadPoolFull(Exception):

	def __init__(self, capacity):
		Exception.__init__(self, "Runner thread pool has reached full capacity (%s)" % (capacity))
		self.capacity = capacity


class Runner:
	"""Wraps a Rule or Action in a separate thread an invoked the 'onEnded'
	callback once the rule is executed."""

	POOL = Pool(50)

	@classmethod
	def Create(cls, runable, context=None, iteration=None, id=None):
		if Runner.POOL.canAdd():
			runner = Runner(runable, context, iteration, Runner.POOL, id=id)
			Runner.POOL.add(runner)
			return runner
		else:
			return None

	def __init__(self, runable, context=None, iteration=None, pool=None, id=None):
		assert isinstance(runable, Action) or isinstance(runable, Rule)
		self._onRunEnded  = None
		self.runable      = runable
		self.context      = context
		self.result       = None
		self.iteration    = iteration
		self.creationTime = now()
		self.startTime    = -1
		self.endTime      = -1
		self.duration     = 0
		self.pool         = pool
		self.id           = id
		self._thread      = threading.Thread(target=self._run)
		# We want the threads to be "daemonic", ie. they will all stop once
		# the main monitoring stops.
		# SEE: http://docs.python.org/release/2.5.2/lib/thread-objects.html
		self._thread.setDaemon(True)

	def getID( self ):
		return self.id

	def onRunEnded(self, callback):
		self._onRunEnded = callback
		return self

	def hasFailed(self):
		return not (isinstance(self.result, Success))

	def run(self, *args):
		self.args = args
		self._thread.start()
		return self

	def _run(self):
		self.startTime = now()
		try:
			self.result = self.runable.run(*self.args)
			if isinstance(self.result, Success) or isinstance(self.result, Failure):
				self.result.duration = self.duration
		except Exception as e:
			self.result = e
			Logger.Err("Exception occured in 'run' with: %s %s" % (e, self.runable))
			Logger.Traceback()
		self.endTime  = now()
		self.duration = self.endTime - self.startTime
		try:
			if self.pool:
				self.pool.remove(self)
		except Exception as e:
			Logger.Err("Exception occured in 'run/pool' with: %s %s" % (e, self.runable))
			Logger.Traceback()
		try:
			if self._onRunEnded:
				self._onRunEnded(self)
		except Exception as e:
			Logger.Err("Exception occured in 'run/onRunEnded' with: %s %s" % (e, self.runable))
			Logger.Traceback()


# -----------------------------------------------------------------------------
#
# MONITOR
#
# -----------------------------------------------------------------------------

class Monitor:
	"""The monitor is at the core of the Monitoring. Rules declared in registered
	services are run, and actions are executed according to the result."""

	FREQUENCY = Time.s(5)

	def __init__(self, *services):
		"""Creats a new monitor with the  given services."""
		self.services              = []
		self.isRunning             = False
		self.freq                  = self.FREQUENCY
		self.logger                = Logger(prefix="monitoring ")
		self.iteration             = 0
		self.iterationLastDuration = 0
		self.runners               = {}
		self.reactions             = {}
		map(self.addService, services)

	def every( self, freq ):
		assert freq >= 0
		self.freq = freq
		return self

	def getFrequency( self ):
		f = self.freq
		for _ in self.services:
			g = _.getFrequency()
			if g != 0:
				f = min(f, g) if f>=0 else g
		return f

	def on( self, **reactions ):
		for event, callback in reactions.items():
			self.onEvent(event, callback)
		return self

	def onEvent( self, name, callback ):
		callbacks = self.reactions.setdefault(name, [])
		if callback not in callbacks: callbacks.append(callback)

	def trigger( self, name ):
		for callback in self.reactions.get(name,[]):
			callback()

	def addService(self, service):
		"""Adds a service to this monitor."""
		self.services.append(service)
		return self

	def run(self, iterations=-1, events=None):
		"""Runs this Monitor for the given number of `iterations`.
		If `iterations` is `-1` then the monitor will run indefinitely."""
		Signals.Setup()
		self.isRunning = True
		for event in (events or []):
			self.trigger(event)
		while self.isRunning:
			it_start = now()
			next_run = it_start + self.freq
			# For each registered service
			for service in self.services:
				# For each rule within the service
				for rule in service.rules:
					# We check if the rule has to be executed right now
					# or a little bit later
					to_wait = rule.shouldRunIn()
					if to_wait > 0:
						# If we have to wait, then we indicate what would
						# be the time to run the rule
						next_run = min(now() + to_wait, next_run)
					else:
						# The rule has to be run right now, so we try to get a
						# runner for it. This might fail if we can't create the
						# runner
						runner = self.getRunnerForRule(rule, service, self.iteration)
						if runner:
							rule.touch()
							runner.run()
						next_run = min(
							now() + rule.getFrequency(),
							next_run
						)
			# We've reached the end of an iteration
			duration                   = now() - it_start
			self.iterationLastDuration = duration
			self.logger.info(self.getStatusMessage())
			self.iteration             += 1
			# Sleeps waiting for the next run
			sleep_time = max(0, next_run - now())
			if sleep_time > 0:
				if sleep_time > 1000:
					self.logger.info("Sleeping for %0.2fs" % (sleep_time / 1000.0))
				time.sleep(sleep_time / 1000.0)
			# In case we've exceeded the number of iterations, we stop the loop
			if iterations > 0 and self.iteration >= iterations:
				self.isRunning = False

	def getRunnerForRule( self, rule, service, iteration ):
		try:
			return self._createRunner( rule, service, iteration, self.onRuleEnded )
		except RunnerStillRunning as e:
			if self.iteration - e.runner.iteration < 5:
				self.logger.err("Previous iteration's rule is still running: %s, you should increase its frequency." % (rule))
			else:
				self.logger.err("Previous iteration's rule %s seems to be still stuck after %s iteration." % (rule, e.runner.iteration - self.iteration))
			return None
		except RunnerThreadPoolFull as e:
			self.logger.err("Cannot create runner for rule: %s (thread pool reached full capacity)" % (rule))
			return None

	def getRunnerForAction( self, rule, action, service, iteration ):
		runner_id = "%s:%s" % (str(rule), str(action))
		try:
			return self._createRunner( action, service, iteration, self.onActionEnded, runner_id )
		except RunnerStillRunning as e:
			if self.iteration - e.runner.iteration < 5:
				self.logger.err("Previous iteration's action is still running: %s.%s, you should increase its frequency." % (rule, str(action)))
			else:
				self.logger.err("Previous iteration's action %s.%s seems to be still stuck after %s iteration." % (rule, str(action), e.runner.iteration - self.iteration))
			return None
		except RunnerThreadPoolFull as e:
			self.logger.err("Cannot create runner for action: %s.%s (thread pool reached full capacity)" % (rule, str(action)))
			return None

	def onRuleEnded(self, runner):
		"""Callback bound to 'Runner.onRunEnded', trigerred once a rule was executed.
		If the rule failed, actions will be executed."""
		rule      = runner.runable
		service   = runner.context
		iteration = runner.iteration
		if isinstance(runner.result, Success):
			if rule.success:
				for action in rule.success:
					action_object = service.getAction(action)
					action_runner = self.getRunnerForAction(rule, action_object, service, self.iteration)
					if action_runner:
						action_runner.run(self, service, rule, runner)
		elif isinstance(runner.result, Failure):
			self.logger.err("Failure on ", rule, ":", runner.result)
			if rule.fail:
				#self.logger.info("Failure actions:", ", ".join(rule.fail))
				for action in rule.fail:
					action_object = service.getAction(action)
					action_runner = self.getRunnerForAction(rule, action_object, service, self.iteration)
					if action_runner:
						action_runner.run(self, service, rule, runner)
			else:
				#self.logger.info("No failure action to trigger")
				pass
		else:
			self.logger.err("Rule did not return Success or Failure instance: %s, got %s" % (rule, runner.result))
		# We unregister the runnner
		del self.runners[runner.getID()]

	def onActionEnded( self, runner ):
		# We unregister the runnner
		del self.runners[runner.getID()]

	def _createRunner(self, runable, context, iteration, callback, runableId=None):
		"""Creates a runner for the given runable, making sure that it won't
		be started twice, raising `RunnerStillRunning`
		or `RunnerThreadPoolFull` in case of problems."""
		# FIXME: we should prefix the ID with the Rule name, if any
		if runableId is None:
			runable_id = str(runable)
		else:
			runable_id = runableId
		if runable_id in self.runners:
			runner = self.runners[runable_id]
			raise RunnerStillRunning(runner)
		else:
			runner = Runner.Create(runable, context=context, iteration=iteration, id=runable_id)
			if runner:
				self.runners[runner.getID()] = runner
				runner.onRunEnded(callback)
				return runner
			else:
				raise RunnerThreadPoolFull(Runner.POOL.capacity)

	def getStatusMessage(self):
		return "#%d (runners=%d,threads=%d,duration=%0.2fs)" % (self.iteration, Runner.POOL.size(), threading.activeCount(), self.iterationLastDuration)

# -----------------------------------------------------------------------------
#
# GLOBALS
#
# -----------------------------------------------------------------------------

SUCCESS = Success()
FAILURE = Failure()

def command(args):
	if len(args) != 1:
		print ("Usage: monitoring FILE")
	else:
		with open(args[0],"r") as f:
			exec (f.read())

# EOF - vim: tw=80 ts=4 sw=4 noet
