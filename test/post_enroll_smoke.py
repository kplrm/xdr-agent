#!/usr/bin/env python3
"""Run the real Agent through enrollment under bounded, non-root load."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

if os.geteuid() == 0:
    raise SystemExit("run make test without sudo; smoke test will not start the Agent as root")

COUNTS = {}

class Coordinator(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self):
        COUNTS[self.path] = COUNTS.get(self.path, 0) + 1
        if self.command == "POST":
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.dumps({"enrollment_id": "smoke-agent", "indexed": 1,
                           "pending_commands": [], "message": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = respond
    do_GET = respond


def cpu_seconds(pid):
    try:
        # Parentheses in comm make a plain whitespace split incorrect.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        hz = os.sysconf("SC_CLK_TCK")
        return (sum(int(fields[i]) for i in (11, 12)) / hz,
                sum(int(fields[i]) for i in (13, 14)) / hz)
    except (FileNotFoundError, ProcessLookupError):
        return (0.0, 0.0)


with tempfile.TemporaryDirectory(prefix="xdr-post-enroll-") as temp:
    root = Path(temp)
    binary = root / "xdr-agent"
    subprocess.run([os.environ.get("GO", "go"), "build", "-o", str(binary), "./cmd/xdr-agent"], check=True)
    server = HTTPServer(("127.0.0.1", 0), Coordinator)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = root / "config.json"
    config.write_text(json.dumps({
        "control_plane_url": f"http://127.0.0.1:{server.server_port}",
        "enrollment_token": "smoke-token", "state_path": str(root / "state.json"),
        "detection_prevention": {"mode": "detect"}, "max_cpu_cores": 1,
        # Deliberately request rapid polling; the Agent must apply its safety floor.
        "telemetry_interval_seconds": 1, "telemetry_ship_interval_seconds": 2,
        "security_ship_interval_seconds": 2, "heartbeat_interval_seconds": 2,
        "command_poll_interval_seconds": 2, "request_timeout_seconds": 1,
        "logging": {"ship": {"enabled": False}},
    }))
    with (root / "agent.log").open("w+") as log:
        agent = subprocess.Popen([str(binary), "run", "--config", str(config)],
                                 stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        failure = None
        workload = None
        agent_cpu = child_cpu = 0.0
        try:
            os.setpriority(os.PRIO_PROCESS, agent.pid, 19)
            os.sched_setaffinity(agent.pid, {min(os.sched_getaffinity(0))})
            resource.prlimit(agent.pid, resource.RLIMIT_CPU, (5, 5))
            started = time.monotonic()
            workload_sent = False
            while time.monotonic() - started < 12:
                if agent.poll() is not None:
                    failure = f"Agent exited early: {agent.returncode}"
                    break
                agent_cpu, child_cpu = cpu_seconds(agent.pid)
                if agent_cpu + child_cpu > 4:
                    failure = ("Agent and YARA children exceeded four CPU seconds "
                               f"(agent={agent_cpu:.2f}s, children={child_cpu:.2f}s)")
                    break
                if COUNTS.get("/api/v1/agents/heartbeat", 0) and not workload_sent:
                    workload = subprocess.Popen(["/usr/bin/sleep", "7"], stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
                    workload_sent = True
                time.sleep(0.2)
            if not failure and (not COUNTS.get("/api/v1/agents/enroll") or
                                not COUNTS.get("/api/v1/agents/heartbeat") or
                                not COUNTS.get("/api/v1/agents/telemetry")):
                failure = f"post-enrollment flow incomplete: {COUNTS}"
        finally:
            if workload is not None:
                if workload.poll() is None:
                    workload.terminate()
                workload.wait(timeout=3)
            if agent.poll() is None:
                os.killpg(agent.pid, signal.SIGTERM)
                try:
                    agent.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(agent.pid, signal.SIGKILL)
                    agent.wait(timeout=3)
            server.shutdown()
        if failure:
            log.seek(0)
            print("\n".join(log.read().splitlines()[-20:]), file=sys.stderr)
            raise SystemExit(failure)
print(f"PASS: bounded post-enrollment Agent startup, heartbeat, and telemetry "
      f"(CPU: agent {agent_cpu:.2f}s, children {child_cpu:.2f}s / 12s)")
