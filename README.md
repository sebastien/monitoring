# Monitoring

Server monitoring and data-collection daemon

## Description

Monitoring is an API with a DSL feel to write monitoring daemons in Python.

## Use Cases

Monitoring works well for the following tasks:

* to be notified when incidents happen (email, XMPP, ZeroMQ...)
* automatic actions to be taken (restart, rm, git pull...)
* to collect system statistics for further processing e.g. graphs
* tie into existing/third-party Python code
* play along nicely with existing deployment/configuration ecosystem (fabric/cuisine)

## Overview

* monitoring DSL: declarative programming to define monitoring strategy
* wide spectrum: from data collection and incident reporting to taking automatic actions
* Small, easy to read, a single file API
* Revised BSD License
* written in Python

## Installation

```bash
python setup.py install
```

or

```bash
easy_install monitoring
```

## Quick Start

Create a monitoring script, for example `my_monitor.py`:

```python
from monitoring import *

Monitor(
    Service(
        name="my-service",
        monitor=(
            HTTP(
                GET="http://localhost:8080/health",
                freq=Time.s(30),
                fail=[Log("Service is down!")],
            ),
        ),
    )
).run()
```

Run it with:

```bash
python my_monitor.py
```

Or using the monitoring command:

```bash
monitoring my_monitor.py
```

### Running with Curl

If you have the repository cloned locally and want to run scripts without keeping the entire codebase installed, download the main CLI on-the-fly:

```bash
curl -s https://raw.githubusercontent.com/sebastien/monitoring/main/src/sh/monitoring.sh | bash -s examples/system-health.py
```

This downloads `monitoring.py`, pipes it to bash, and executes it with your local script, using the downloaded monitoring library.

## Examples

See the `examples/` directory for more usage examples:

* `system-health.py`: Monitor system metrics like CPU, memory, disk usage
* `http-latency.py`: Monitor HTTP response times
* `http-ping-restart.py`: Ensure HTTP services stay up by restarting on failure
* `service-tmux.py`: Run services in tmux sessions (imports `TmuxService` from `monitoring`)

## API Overview

### Core Classes

* `Monitor`: The main monitoring engine that runs services
* `Service`: A collection of rules and actions
* `Rule`: Defines what to monitor (e.g., HTTP checks, system health)
* `Action`: Defines what to do on success/failure (e.g., log, email, restart)

### Built-in Rules

* `HTTP`: Check HTTP endpoints
* `SystemHealth`: Monitor CPU, memory, disk usage
* `SystemInfo`: Collect system statistics
* `Bandwidth`: Measure network bandwidth
* `ProcessInfo`: Monitor process statistics
* `Delta`: Track changes over time

### Built-in Actions

* `Log`: Log messages to files or stdout
* `Email`: Send email notifications
* `XMPP`: Send XMPP messages
* `Run`: Execute shell commands
* `Restart`: Restart processes
* `Incident`: Trigger actions after multiple failures
* `TmuxRun`: Execute commands in tmux windows

### Daemon Service Classes

* `DaemonService`: Base class for implementing services with start/stop/status directives
* `TmuxService`: Manages long-running processes in tmux sessions
* `WebService`: Manages web applications with tmux and HTTP health checks

### Utilities

* `Time`: Time unit conversions (ms, s, m, h, d, w)
* `Size`: Size unit conversions (B, KB, MB, GB)
* `Process`: Process management utilities
* `System`: System information utilities
* `Tmux`: Tmux session management

## More Information

Read the presentation on Monitoring: http://ur1.ca/45ku5 (previously named Watchdog).

## License

Revised BSD License

## Author

Sébastien Pierre <sebastien.pierre@gmail.com>

## Repository

https://github.com/sebastien/monitoring