#!/usr/bin/env python
from daemonwatch import *
import json
config = json.loads(file("email.passwd").read())
action = Email(
	"sebastien@ffctn.com",
	"[Daemonwatch] Test", "Sample message", 
	email["smtp"],email["user"],email["password"]
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
