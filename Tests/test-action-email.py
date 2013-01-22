#!/usr/bin/env python
from monitoring import *
import json
config = json.loads(file("email.passwd").read())
action = Email(
	"sebastien@ffctn.com",
	"[Monitoring] Test", "Sample message", 
	config["smtp"],config["user"],config["password"]
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
