#!/usr/bin/env python
from monitoring import *
__doc__ = """
Fail every second, and only triggers the log result after at least 5 failures over 10 seconds
"""
Monitor(
	Service(
		name = "fail-incident",
		monitor = (
			Fail(Time.s(1), Incident(errors=5, during=Time.s(10), actions=LogResult()))
		)
	)
).run()
