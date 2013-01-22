from monitoring import *
Monitor (
	Service(
		name    = "system-health",
		monitor = (
			SystemInfo(freq=Time.s(1),
				success = (
					LogResult("myserver.system.mem=",  extract=lambda r,_:r["memoryUsage"]),
					LogResult("myserver.system.disk=", extract=lambda r,_:reduce(max,r["diskUsage"].values())),
					LogResult("myserver.system.cpu=",  extract=lambda r,_:r["cpuUsage"]),
				)
			),
			Delta(
				Bandwidth("eth0", freq=Time.s(1)),
				extract = lambda v:v["total"]["bytes"]/1000.0/1000.0,
				success = [LogResult("myserver.system.eth0.sent=")]
			),
			SystemHealth(
				cpu=0.90, disk=0.90, mem=0.90,
				freq=Time.s(60),
				fail=[Log(path="monitoring-system-failures.log")]
			),
		)
	)
).run()

