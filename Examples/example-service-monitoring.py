#!/usr/bin/env python
from daemonwatch import *
Monitor(
	Service(
		name = "google-search-latency",
		monitor = (
			HTTP(
				GET="http://www.google.ca/search?q=daemonwatch",
				freq=Time.s(1),
				timeout=Time.ms(80),
				fail=[
					Print("Google search query took more than 50ms")
				]
			)
		)
	)
).run()
