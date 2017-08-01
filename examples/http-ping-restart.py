#!/usr/bin/env python
from monitoring import *
__doc__ = """How to ensure that a given (HTTP) service stays up and running."""
Monitor(
	Service(
		name=__file__[0].split(".")[0],
		monitor=(
			HTTP(
				# We monitor the 'http://localhost:8000' URL, which is where
				# we expect the 'myservice' to be bound
				GET="http://localhost:8000/",
				freq=Time.ms(500),
				fail=[
					Incident(
						# If we have 5 errors during 5 seconds...
						errors=5,
						during=Time.s(5),
						actions=[
							# We kill the 'myservice-start.py' script if it exists
							# and (re)start it, so that the 'http://localhost:8000' will
							# become available
							# NOTE: Restart will make the process a child of the monitoring, so
							# you might prefer to use something like upstart
							Restart("myservice-start.py")
						]
					)
				]
			)
		)
	)
).run()
