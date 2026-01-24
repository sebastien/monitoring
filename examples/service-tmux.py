from monitoring import TmuxService
import time

service = TmuxService("monitoring-example", command="watch -n1 date")
print(
	"#1/3 Starting a tmux session named 'monitoring-example' running 'watch -n1 date'"
)
service.start()
print(
	"#2/3 Connect to the tmux session using: 'tmux attach -t monitoring-example' (you have 10s)…"
)
time.sleep(10)
print("#3/3 Stopping the service in the tmux session")
service.stop()
