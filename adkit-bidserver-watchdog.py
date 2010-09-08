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

Monitor (

	Service(
		name    = "bidserver",

		monitor = (
			HTTP(
				GET=ADKIT_BIDSERVICE+"/api/ping", freq=Time.ms(1000), timeout=Time.ms(5000),
				fail=["logTime"],
				success=["logTime"]
			),
			Mem (
				max=Size.MB(1200), freq=Time.ms(1000),
				fail=["restart", "log"]
			),
		),

		actions = dict(
			log     = Log     (path=LOG_DIR + "/adkit-bidserver-failures.log", stdout=True),
			logTime = LogTime ("bidserver.pingTimeMS", path=LOG_DIR + "/adkit-bidserver-stats.log", stdout=True),
			#restart = Restart ()
		)

	)

).run()

# EOF
