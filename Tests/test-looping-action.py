#!/usr/bin/env python
from   monitoring import *
import time

__doc__ = """
In this test we create a LoopingAction (an action that will never end). We want
to make sure that at the third iteration the monitoring won't be able to start
the LoopingAction.
"""

Runner.POOL.setCapacity(10)

class LoopingAction(Action):

	def run(self, monitor, service, rule, runner ):
		iteration = 0
		while True:
			self.info("Running LoopingAction:", iteration)
			time.sleep(1)
			iteration += 1
Monitor(
	Service(
		name = "test-looping-action",
		monitor = (
			Always(
				freq   =Time.s(1),
				actions=[LoopingAction()]
			)
		)
	)
).run(3)
