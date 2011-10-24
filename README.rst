Watchdog - Server monitoring and data-collection Daemon
=======================================================

We want...
----------
* to be notified when incidents happen (email, XMPP, ZeroMQ...)
* automatic actions to be taken (restart, rm, git pull...)
* to collect system statistics for further processing e.g. graphs
* tie into existing/third-party Python code
* play along nicely with existing deployment/configuration ecosystem
  (fabric/cuisine)

Overview
--------
* monitoring DSL: declarative programming to define monitoring
  strategy
* wide spectrum: from data collection and incident reporting to taking
  automatic actions
* Small, easy to read, a single file API
* Revised BSD License
* written in Python

Use Cases
---------
* ensure service availability: test and start/stop when problems
* collect system statistics/data, log locally and/or remotely
* alert on system/service health, take actions

Installation
------------
Sorry, no 'setup.py' for now. Just have a look in the 'Examples' and 'Test'
directories for more info. Just be sure that 'Source/watchdog.py' is
in 'sys.path'.

More?
-----
Read the `presentation on Watchdog <http://ur1.ca/45ku5>`_
