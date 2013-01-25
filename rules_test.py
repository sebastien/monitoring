#!/usr/bin/env python
from watchdog import *
Monitor(
    Service(
        name = "google",
        monitor = (
            HTTP(
                GET="http://google.com/",
                freq=Time.s(60),
                timeout=Time.ms(50),
                fail=[
                    Print("google took more than 50ms to reply")
                ]
            )
        )
    ),
    Service(
        name = "local health",
        monitor = (
            SystemHealth(
                freq = Time.s(5),
                cpu = 0.1,
                mem = 0.01,
                disk = 0.1,
                fail = [
                    Print("local system is overloaded")
                ]
            )
        )
    )
).run()
