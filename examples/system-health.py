#!/usr/bin/env python
from monitoring import *
__doc__ = """
Shows how to periodically query a system's memory, disk & cpy usage
and logs to a file when the system metrics exceeds the values.
"""
Monitor (
	Service(
		name=__file__[0].split(".")[0],
		monitor = (
			SystemInfo(freq=Time.s(5),
				success = (
					LogResult("myserver.system.mem=",  extract=lambda r,_:r["memoryUsage"]),
					LogResult("myserver.system.disk=", extract=lambda r,_:reduce(max,r["diskUsage"].values())),
					LogResult("myserver.system.cpu=",  extract=lambda r,_:r["cpuUsage"]),
				)
			),
			Delta(
				Bandwidth("eth0", freq=Time.s(5)),
				extract = lambda v:v["total"]["bytes"]/1000.0/1000.0,
				success = [LogResult("myserver.system.eth0.sent=")]
			),
			SystemHealth(
				cpu=0.90, disk=0.90, mem=0.90,
				freq=Time.s(60),
				fail=[Log(path=__file__.split(".")[0] + "-errors.log")]
			),
		)
	)
).run()

