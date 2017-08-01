#!/usr/bin/env python
from monitoring import *
__doc__ = """
Queries the Google search engin and fail if the query takes
more than 80ms.
"""
Monitor(
	Service(
		name=__file__[0].split(".")[0],
		monitor = (
			HTTP(
				GET="http://www.google.ca/search?q=monitoring",
				freq=Time.s(1),
				timeout=Time.ms(80),
				fail=[
					Print("Google search query took more than 50ms")
				]
			)
		)
	)
).run()
