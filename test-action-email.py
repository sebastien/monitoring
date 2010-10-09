#!/usr/bin/env python
from watchdog import *
print Email(
	"sebastien@ffctn.com",
	"[Watchdog] Test", "Sample message", 
	"smtp.gmail.com", "mail.agent@ffctn.com", "ffctnmailagent"
).send()
Monitor(
	Service(
		name = "test-action-email",
		monitor = (
			Fail(Time.s(10), actions=Email(
				"sebastien@ffctn.com",
				"[Watchdog] Failure", "Rule failed", 
				"smtp.gmail.com", "mail.agent@ffctn.com", "ffctnmailagent"
			)),
			Succeed(Time.s(10), actions=Email(
				"sebastien@ffctn.com",
				"[Watchdog] Failure", "Rule failed", 
				"smtp.gmail.com", "mail.agent@ffctn.com", "ffctnmailagent"
			))
		)
	)
).run()
