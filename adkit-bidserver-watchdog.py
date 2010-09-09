from watchdog import *

LOG_DIR              = "/tmp"
ADKIT_BIDSERBER_JAR  = "/home/sebastien/Projects/Private/AdKit/Distribution/adkit-bidserver.jar"
ADKIT_BIDSERVER_DIR  = "/home/sebastien/Projects/Private/AdKit/Services/BidServer"
ADKIT_BIDSERVER_CONF = "/home/sebastien/Projects/Private/AdKit/Services/BidServer/bidserver.conf"
ADKIT_BIDSERVER      = "java -server -XX:+AggressiveOpts -XX:+UseFastAccessorMethods -jar %s %s" % (ADKIT_BIDSERBER_JAR, ADKIT_BIDSERVER_CONF)

ADKIT_BIDSERVICE     = "bd-1.weservemanyads.com:9030"

class LogTime(Log):

	def __init__( self, statname, path=None, stdout=True ):
		Log.__init__(self, path, stdout)
		self.statname = statname

	def successMessage( self, monitor, service, rule, runner ):
		return "%s STAT:%s.success=%f" % (self.preamble(monitor, service, rule, runner), self.statname, runner.duration)

	def failureMessage( self, monitor, service, rule, runner ):
		return "%s STAT:%s.failure=%f" % (self.preamble(monitor, service, rule, runner), self.statname, runner.duration)

class LogResult(Log):

	def __init__( self, message, path=None, stdout=True, process=lambda _:_ ):
		Log.__init__(self, path, stdout)
		self.message   = message
		self.processor = process

	def successMessage( self, monitor, service, rule, runner ):
		return "%s %s %s" % (self.preamble(monitor, service, rule, runner), self.message, self.processor(runner.result.value))

class MeasureBandwidth(Rule):

	def __init__( self, interface, freq, fail=(), success=() ):
		Rule.__init__(self, freq, fail, success)
		self.interface = interface

	def run( self ):
		res =  System.GetInterfaceStats()
		if res.get(self.interface):
			return Success(res[self.interface])
		else:
			return Failure("Cannot find data for interface: %s" % (self.interface))

class ProcInfo(Rule):

	def __init__( self, command, freq, fail=(), success=() ):
		Rule.__init__(self, freq, fail, success)
		self.command = command

	def run( self ):
		pid =  Process.GetWith(self.command, lambda a,b:a.find(b) != -1)
		if pid:
			pid  = pid[0]
			info = Process.Info(pid)
			if info["exists"]:
				return Success(info)
			else:
				return Failure("Process %s does not exists anymore" % (pid))
		else:
			return Failure("Cannot find process with command like: %s" % (self.command))


Monitor (

	Service(
		name    = "bidserver-stats",
		monitor = (
			Delta(
				MeasureBandwidth("eth0", freq=Time.ms(1000)),
				extract = lambda v:v["total"]["bytes"]/1000.0/1000.0,
				success = [LogResult("STAT:bidserver.eth1.total=")]
			),
			ProcInfo(command="bidserver.jar", freq=Time.ms(1000),
				success = (
					LogResult("STAT:bidserver.process.running=", process=lambda v:v["running"]),
					LogResult("STAT:bidserver.process.fd=", process=lambda v:v["fd"]),
					LogResult("STAT:bidserver.process.threads=", process=lambda v:v["threads"]),
				)
			),
		)
	),

	# Service(
	# 	name    = "bidserver",

	# 	monitor = (
	# 		HTTP(
	# 			GET=ADKIT_BIDSERVICE+"/api/ping", freq=Time.ms(1000), timeout=Time.ms(5000),
	# 			fail=["logTime"],
	# 			success=["logTime"]
	# 		),
	# 		HTTP(
	# 			GET=ADKIT_BIDSERVICE+"/google/stats/qps", freq=Time.ms(1000), timeout=Time.ms(5000),
	# 			success=[LogResult("STAT:bidserver.qps=", path=LOG_DIR + "/adkit-bidserver-stats.log")]
	# 		),
	# 		HTTP(
	# 			GET=ADKIT_BIDSERVICE+"/google/stats/processingTime", freq=Time.ms(1000), timeout=Time.ms(5000),
	# 			success=[LogResult("STAT:bidserver.processingTime=", path=LOG_DIR + "/adkit-bidserver-stats.log")]
	# 		),
	# 		Mem (
	# 			max=Size.MB(1200), freq=Time.ms(1000),
	# 			fail=["restart", "log"]
	# 		),
	# 	),

	# 	actions = dict(
	# 		log     = Log     (path=LOG_DIR + "/adkit-bidserver-failures.log", stdout=True),
	# 		logTime = LogTime ("bidserver.pingTimeMS", path=LOG_DIR + "/adkit-bidserver-stats.log", stdout=True),
	# 		#restart = Restart ()
	# 	)

	# )

).run()

# EOF
