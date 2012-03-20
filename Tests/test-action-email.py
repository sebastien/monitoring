#!/usr/bin/env python
from daemonwatch import *
action = Email(
	"sebastien@ffctn.com",
	"[Daemonwatch] Test", "Sample message", 
	"smtp.gmail.com", "mail.agent@ffctn.com", "ffctnmailagent"
)
Monitor(
	Service(
		name = "test-action-email",
		monitor = (
			Fail   (Time.s(10), actions=action),
			Succeed(Time.s(10), actions=action)
		)
	)
).run()
