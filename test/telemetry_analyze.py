#!/usr/bin/env python3
"""
telemetry_analyze.py — Deep analysis of captured xdr-agent telemetry events.

Validates every event against the expected ECS schema for each of the 13
telemetry collectors.  Reports:

  1. ECS envelope compliance
  2. Per-collector field correctness
  3. MITRE ATT&CK consistency
  4. Timestamp sanity
  5. Payload nesting correctness
  6. Field completeness (empty / zero required fields)
  7. event.severity range
  8. Type correctness (number vs string, array vs scalar)
  9. Duplicate / misnamed / misparsed fields
 10. Collector coverage

Usage:
    python3 test/telemetry_analyze.py <captured_events.json> [--json report.json]
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── colour helpers ──────────────────────────────────────────────────────────
COLORS = {
    "R": "\033[0;31m",
    "G": "\033[0;32m",
    "Y": "\033[0;33m",
    "C": "\033[0;36m",
    "B": "\033[1m",
    "N": "\033[0m",
}

def _c(tag: str, text: str) -> str:
    return f"{COLORS.get(tag, '')}{text}{COLORS['N']}"

# ─── Collector Spec ──────────────────────────────────────────────────────────
# Each spec defines expected envelope values and required payload fields.
# Field types: "str", "int", "float", "bool", "list", "dict", "str|list"

EnvelopeSpec = dict[str, Any]
FieldSpec = dict[str, str]  # path -> expected type

class CollectorSpec:
    """Expected schema for one telemetry collector."""

    def __init__(
        self,
        name: str,
        event_module: str,
        event_types: list[str],
        event_category: str,
        event_kind: str,
        severity: int | list[int] | None = None,
        tags_must_include: list[str] | None = None,
        mitre_tactic: str | None = None,
        mitre_technique: str | list[str] | None = None,
        required_payload: dict[str, str] | None = None,
        optional_payload: dict[str, str] | None = None,
        # Payload paths that carry threat/event info inside payload (known issue)
        payload_envelope_dups: list[str] | None = None,
    ):
        self.name = name
        self.event_module = event_module
        self.event_types = event_types
        self.event_category = event_category
        self.event_kind = event_kind
        self.severity = severity
        self.tags_must_include = tags_must_include or []
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.required_payload = required_payload or {}
        self.optional_payload = optional_payload or {}
        self.payload_envelope_dups = payload_envelope_dups or []


# ── Define all 13 collector specs ────────────────────────────────────────────

SPECS: list[CollectorSpec] = [
    # 1a — Process Start
    CollectorSpec(
        name="Process (start)",
        event_module="telemetry.process",
        event_types=["process.start"],
        event_category="process",
        event_kind="event",
        tags_must_include=["process", "telemetry"],
        required_payload={
            "process.pid": "int",
            "process.ppid": "int",
            "process.name": "str",
            "process.state": "str",
            "process.start_time": "int",
            "process.entity_id": "str",
            "process.session_id": "int",
            "process.tty": "int",
            "process.user.id": "int",
            "process.group.id": "int",
            "process.effective_user.id": "int",
            "process.effective_group.id": "int",
            "process.cap_eff": "str",
            "process.threads.count": "int",
            "process.fd_count": "int",
            "process.memory.rss": "int",
            "process.memory.vms": "int",
            "process.io.read_bytes": "int",
            "process.io.write_bytes": "int",
        },
        optional_payload={
            "process.executable": "str",
            "process.command_line": "str",
            "process.args": "list",
            "process.working_directory": "str",
            "process.user.name": "str",
            "process.group.name": "str",
            "process.hash.sha256": "str",
            "process.cpu.pct": "float",
            "process.parent.pid": "int",
            "process.parent.ppid": "int",
            "process.parent.name": "str",
            "process.parent.executable": "str",
            "process.parent.command_line": "str",
            "process.parent.args": "list",
            "process.parent.entity_id": "str",
            "process.ancestors": "list",
            "process.group_leader.pid": "int",
            "process.group_leader.name": "str",
            "process.group_leader.entity_id": "str",
            "process.env": "dict",
            "process.script.path": "str",
            "process.script.content": "str",
            "process.script.length": "int",
            "container.id": "str",
        },
    ),
    # 1b — Process End
    CollectorSpec(
        name="Process (end)",
        event_module="telemetry.process",
        event_types=["process.end"],
        event_category="process",
        event_kind="event",
        tags_must_include=["process", "telemetry"],
        required_payload={
            "process.pid": "int",
            "process.ppid": "int",
            "process.name": "str",
            "process.state": "str",
            "process.start_time": "int",
            "process.entity_id": "str",
            "process.session_id": "int",
            "process.user.id": "int",
            "process.group.id": "int",
        },
        optional_payload={
            "process.executable": "str",
            "process.command_line": "str",
            "process.args": "list",
            "process.working_directory": "str",
            "process.tty": "int",
            "process.effective_user.id": "int",
            "process.effective_group.id": "int",
            "process.cap_eff": "str",
            "process.threads.count": "int",
            "process.fd_count": "int",
            "process.memory.rss": "int",
            "process.memory.vms": "int",
            "process.io.read_bytes": "int",
            "process.io.write_bytes": "int",
            "process.cpu.pct": "float",
            "process.parent.pid": "int",
            "process.parent.ppid": "int",
            "process.parent.name": "str",
            "process.parent.executable": "str",
            "process.parent.command_line": "str",
            "process.parent.args": "list",
            "process.parent.entity_id": "str",
            "process.ancestors": "list",
            "process.group_leader.pid": "int",
            "process.group_leader.name": "str",
            "process.group_leader.entity_id": "str",
            "container.id": "str",
        },
    ),
    # 2 — FIM
    CollectorSpec(
        name="FIM",
        event_module="telemetry.file",
        event_types=["file.created", "file.modified", "file.attrs_changed", "file.deleted"],
        event_category="file",
        event_kind="event",
        tags_must_include=["fim", "file", "telemetry"],
        required_payload={
            "file.path": "str",
            "file.name": "str",
            "file.directory": "str",
            "file.type": "str",
            "file.size": "int",
            "file.mode": "str",
            "file.uid": "int",
            "file.gid": "int",
            "file.owner": "str",
            "file.group": "str",
            "file.hash.sha256": "str",
            "file.entropy": "float",
            "file.header_bytes": "str",
            "file.mtime": "str",
            "file.ctime": "str",
            "fim.action": "str",
        },
        optional_payload={
            "fim.previous.hash.sha256": "str",
            "fim.previous.size": "int",
            "fim.previous.mode": "str",
            "fim.previous.uid": "int",
            "fim.previous.gid": "int",
        },
    ),
    # 3 — File Access
    CollectorSpec(
        name="File Access",
        event_module="telemetry.file.access",
        event_types=["file.access"],
        event_category="file",
        event_kind="event",
        severity=3,
        tags_must_include=["file", "access", "credential-access", "telemetry"],
        mitre_tactic="Credential Access",
        mitre_technique=["T1003.008", "T1552.004"],
        required_payload={
            "file.path": "str",
            "file.name": "str",
            "file.directory": "str",
            "event.action": "str",
        },
        optional_payload={
            "file.event.action": "str",
            "threat.technique.id": "list",
        },
    ),
    # 4 — Network
    CollectorSpec(
        name="Network",
        event_module="telemetry.network",
        event_types=["network.connection_opened", "network.connection_closed"],
        event_category="network",
        event_kind="event",
        tags_must_include=["network", "telemetry"],
        required_payload={
            "source.ip": "str",
            "source.port": "int",
            "destination.ip": "str",
            "destination.port": "int",
            "network.transport": "str",
            "network.type": "str",
            "network.direction": "str",
            "network.community_id": "str",
            "network.state": "str",
            "network.inode": "int",
        },
        optional_payload={
            "source.user.id": "str",
            "source.user.name": "str",
            "process.pid": "int",
            "process.name": "str",
            "process.executable": "str",
        },
    ),
    # 5 — DNS
    CollectorSpec(
        name="DNS",
        event_module="telemetry.dns",
        event_types=["dns.query", "dns.answer"],
        event_category="network",
        event_kind="event",
        tags_must_include=["dns", "network", "telemetry"],
        required_payload={
            "dns.id": "int",
            "dns.type": "str",
            "dns.question.name": "str",
            "dns.question.type": "str",
            "dns.question.class": "str",
            "dns.question.registered_domain": "str",
            "dns.op_code": "str",
            "dns.recursion_desired": "bool",
            "dns.header_flags": "list",
            "source.ip": "str",
            "source.port": "int",
            "destination.ip": "str",
            "destination.port": "int",
            "network.transport": "str",
            "network.type": "str",
            "network.community_id": "str",
        },
        optional_payload={
            "dns.recursion_available": "bool",
            "dns.authoritative": "bool",
            "dns.response_code": "str",
            "dns.answers": "list",
            "dns.answers_count": "int",
            "dns.resolved_ips": "list",
            "process.pid": "int",
            "process.name": "str",
            "process.executable": "str",
        },
    ),
    # 6 — Session
    CollectorSpec(
        name="Session",
        event_module="telemetry.session",
        event_types=[
            "session.logged-in", "session.logged-out", "session.sudo",
            "session.ssh-accepted", "session.ssh-failed", "session.su",
        ],
        event_category="authentication",
        event_kind="event",
        tags_must_include=["session", "authentication", "telemetry"],
        required_payload={
            "event.action": "str",
            "event.outcome": "str",
            "user.name": "str",
            "related.user": "list",
        },
        optional_payload={
            "user.effective.name": "str",
            "session.type": "str",
            "source.ip": "str",
            "source.port": "int",
            "process.pid": "int",
            "process.tty.name": "str",
            "process.command_line": "str",
            "related.ip": "list",
        },
    ),
    # 7 — System Metrics
    # Note: the first event (baseline) only has memory fields.
    # CPU, diskio, netio require a prior sample for delta calculation.
    CollectorSpec(
        name="System Metrics",
        event_module="telemetry.system",
        event_types=["system.metrics"],
        event_category="host",
        event_kind="metric",
        tags_must_include=["system", "metric"],
        required_payload={
            "system.memory.total": "int",
            "system.memory.free": "int",
            "system.memory.used.bytes": "int",
            "system.memory.used.pct": "float",
        },
        optional_payload={
            "system.cpu.total.pct": "float",
            "system.cpu.user.pct": "float",
            "system.cpu.system.pct": "float",
            "system.cpu.idle.pct": "float",
            "system.cpu.iowait.pct": "float",
            "system.cpu.steal.pct": "float",
            "system.cpu.cores": "int",
            "system.memory.cached": "int",
            "system.memory.buffer": "int",
            "system.memory.actual.free": "int",
            "system.memory.swap.total": "int",
            "system.memory.swap.free": "int",
            "system.memory.swap.used.bytes": "int",
            "system.memory.swap.used.pct": "float",
            "system.diskio.read.bytes": "int",
            "system.diskio.read.ops": "int",
            "system.diskio.write.bytes": "int",
            "system.diskio.write.ops": "int",
            "system.netio.in.bytes": "int",
            "system.netio.in.packets": "int",
            "system.netio.out.bytes": "int",
            "system.netio.out.packets": "int",
        },
    ),
    # 7b — Per-process CPU (emitted by system collector)
    CollectorSpec(
        name="System (Per-Process CPU)",
        event_module="telemetry.system",
        event_types=["process.cpu"],
        event_category="process",
        event_kind="metric",
        tags_must_include=["cpu", "process", "metric"],
        required_payload={
            "process.pid": "int",
            "process.name": "str",
            "process.executable": "str",
            "process.command_line": "str",
            "process.cpu.pct": "float",
        },
    ),
    # 8 — Library
    CollectorSpec(
        name="Library",
        event_module="telemetry.library",
        event_types=["library.loaded", "library.loaded_into_process"],
        event_category="library",
        event_kind="event",
        tags_must_include=["library", "telemetry", "so-loading"],
        mitre_tactic="Defense Evasion",
        mitre_technique="T1574.006",
        required_payload={
            "dll.name": "str",
            "dll.path": "str",
            "dll.hash.sha256": "str",
            "dll.size": "int",
            "description": "str",
        },
        optional_payload={
            "process.pid": "int",
            "process.name": "str",
        },
    ),
    # 9 — Kernel Modules
    CollectorSpec(
        name="Kernel Modules",
        event_module="telemetry.kernel.modules",
        event_types=["kernel.module_load", "kernel.module_unload"],
        event_category="driver",
        event_kind="event",
        severity=[3, 2],  # 3 for load, 2 for unload
        tags_must_include=["kernel", "module", "telemetry"],
        mitre_tactic="Persistence",
        mitre_technique="T1547.006",
        required_payload={
            "driver.name": "str",
            "xdr.kernel_module.name": "str",
            "xdr.kernel_module.size": "int",
            "xdr.kernel_module.ref_count": "int",
            "xdr.kernel_module.deps": "list",
            "xdr.kernel_module.state": "str",
            "xdr.kernel_module.address": "str",
        },
    ),
    # 10 — TTY
    CollectorSpec(
        name="TTY",
        event_module="telemetry.tty",
        event_types=["tty.session_start", "tty.session_end"],
        event_category="process",
        event_kind="event",
        tags_must_include=["tty", "terminal", "session", "telemetry"],
        mitre_tactic="Execution",
        mitre_technique="T1059.004",
        required_payload={
            "process.pid": "int",
            "process.ppid": "int",
            "process.name": "str",
            "process.executable": "str",
            "process.command_line": "str",
            "process.session_id": "int",
            "process.user.id": "int",
            "process.group.id": "int",
            "process.tty.nr": "int",
            "process.tty.name": "str",
        },
    ),
    # 11 — Scheduled Tasks
    CollectorSpec(
        name="Scheduled Tasks",
        event_module="telemetry.scheduled",
        event_types=["scheduled.task_created", "scheduled.task_modified", "scheduled.task_deleted"],
        event_category="configuration",
        event_kind="event",
        severity=3,
        tags_must_include=["scheduled", "cron", "persistence", "telemetry"],
        mitre_tactic="Persistence",
        mitre_technique=["T1053.003", "T1053.006"],
        required_payload={
            "file.path": "str",
            "file.name": "str",
            "xdr.scheduled_task.path": "str",
            "xdr.scheduled_task.type": "str",
            "xdr.scheduled_task.raw_content": "str",
        },
        optional_payload={
            "xdr.scheduled_task.entries": "list",
            "xdr.scheduled_task.previous_content": "str",
        },
    ),
    # 12a — Injection (ptrace)
    CollectorSpec(
        name="Injection (ptrace)",
        event_module="telemetry.injection",
        event_types=["process_injection.ptrace_attach"],
        event_category="intrusion_detection",
        event_kind="alert",
        severity=3,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1055",
        tags_must_include=["injection", "ptrace", "process", "telemetry"],
        required_payload={
            "process.pid": "int",
            "process.name": "str",
            "process.executable": "str",
            "xdr.injection.indicator": "str",
            "xdr.injection.detail": "str",
            "xdr.injection.target.pid": "int",
            "xdr.injection.target.name": "str",
            "xdr.injection.target.exe": "str",
            "description": "str",
        },
        optional_payload={
            "xdr.injection.tracer.pid": "int",
            "xdr.injection.tracer.name": "str",
            "xdr.injection.tracer.exe": "str",
        },
    ),
    # 12b — Injection (anon exec)
    CollectorSpec(
        name="Injection (anon exec)",
        event_module="telemetry.injection",
        event_types=["process_injection.anon_exec_region"],
        event_category="intrusion_detection",
        event_kind="alert",
        severity=3,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1620",
        tags_must_include=["injection", "ptrace", "process", "telemetry"],
        required_payload={
            "process.pid": "int",
            "process.name": "str",
            "process.executable": "str",
            "xdr.injection.indicator": "str",
            "xdr.injection.detail": "str",
            "xdr.injection.target.pid": "int",
            "xdr.injection.target.name": "str",
            "xdr.injection.target.exe": "str",
            "description": "str",
        },
    ),
    # 13a — IPC (Unix socket)
    CollectorSpec(
        name="IPC (Unix Socket)",
        event_module="telemetry.ipc",
        event_types=["ipc.unix_socket.created"],
        event_category="network",
        event_kind="event",
        severity=0,
        tags_must_include=["ipc", "unix-socket", "network", "telemetry"],
        mitre_technique="T1559",
        required_payload={
            "network.unix_socket.path": "str",
            "network.type": "str",
            "network.transport": "str",
            "event.action": "str",
        },
    ),
    # 13b — IPC (Named pipe)
    CollectorSpec(
        name="IPC (Named Pipe)",
        event_module="telemetry.ipc",
        event_types=["ipc.pipe.created"],
        event_category="file",
        event_kind="event",
        severity=2,
        tags_must_include=["ipc", "named-pipe", "file", "telemetry"],
        mitre_technique="T1559",
        required_payload={
            "process.io.pipe_name": "str",
            "file.path": "str",
            "file.name": "str",
            "file.directory": "str",
            "file.type": "str",
            "event.action": "str",
        },
    ),
]

# The 13 logical collectors (for coverage counting)
COVERAGE_COLLECTORS: list[str] = [
    "telemetry.process",
    "telemetry.file",
    "telemetry.file.access",
    "telemetry.network",
    "telemetry.dns",
    "telemetry.session",
    "telemetry.system",
    "telemetry.library",
    "telemetry.kernel.modules",
    "telemetry.tty",
    "telemetry.scheduled",
    "telemetry.injection",
    "telemetry.ipc",
]

# ─── envelope required keys ──────────────────────────────────────────────────
ENVELOPE_REQUIRED = {
    "id": "str",
    "@timestamp": "str",
    "event.type": "str",
    "event.category": "str",
    "event.kind": "str",
    "event.severity": "int",
    "event.module": "str",
    "agent.id": "str",
    "host.hostname": "str",
    "payload": "dict",
}

ENVELOPE_OPTIONAL = {
    "threat.tactic.name": "str",
    "threat.technique.id": "str",
    "threat.technique.subtechnique.id": "str",
    "tags": "list",
}

VALID_KINDS = {"event", "alert", "metric", "state"}
VALID_CATEGORIES = {
    "process", "file", "network", "authentication", "host",
    "library", "driver", "configuration", "intrusion_detection",
}

# ─── helpers ─────────────────────────────────────────────────────────────────

def resolve_nested(obj: dict, dotpath: str) -> Any | None:
    """Resolve a dot-separated path against a nested dict.

    e.g. resolve_nested({"process": {"pid": 42}}, "process.pid") → 42
    """
    parts = dotpath.split(".")
    cur: Any = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return cur


def check_type(value: Any, expected: str) -> bool:
    """Check Python value against our type string."""
    if expected == "str":
        return isinstance(value, str)
    if expected == "int":
        return isinstance(value, (int,)) and not isinstance(value, bool)
    if expected == "float":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "bool":
        return isinstance(value, bool)
    if expected == "list":
        return isinstance(value, list)
    if expected == "dict":
        return isinstance(value, dict)
    if expected == "str|list":
        return isinstance(value, (str, list))
    return True


def type_name(value: Any) -> str:
    """Human-readable type label."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "null"
    return type(value).__name__


def is_empty(value: Any) -> bool:
    """Check if a value is 'empty' in a way that indicates a problem."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    # Note: 0 and False are valid values for ints and bools
    return False


def is_valid_rfc3339(ts: str) -> bool:
    """Check if string is a valid RFC 3339 / ISO 8601 timestamp."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


def is_recent_timestamp(ts: str, max_age_hours: int = 24) -> bool:
    """Check if timestamp is within last N hours."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age = (now - dt).total_seconds()
        return -3600 <= age <= max_age_hours * 3600  # allow 1h future drift
    except Exception:
        return False


def flatten_dict(d: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dict into dot-separated keys."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten_dict(v, key))
        else:
            out[key] = v
    return out


# ─── Finding ─────────────────────────────────────────────────────────────────

class Finding:
    """A single validation finding."""

    def __init__(self, severity: str, check: str, message: str,
                 event_id: str = "", collector: str = ""):
        self.severity = severity   # ERROR, WARN, INFO
        self.check = check
        self.message = message
        self.event_id = event_id
        self.collector = collector

    def __str__(self) -> str:
        tag = {"ERROR": _c("R", "[ERROR]"), "WARN": _c("Y", "[WARN] "),
               "INFO": _c("C", "[INFO] ")}.get(self.severity, "[????]")
        ctx = ""
        if self.collector:
            ctx += f" ({self.collector})"
        if self.event_id:
            ctx += f" [id={self.event_id[:16]}]"
        return f"  {tag} {self.check}: {self.message}{ctx}"

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "check": self.check,
            "message": self.message,
            "event_id": self.event_id,
            "collector": self.collector,
        }


# ─── Analyzer ────────────────────────────────────────────────────────────────

class TelemetryAnalyzer:
    """Runs all validation checks over a list of captured events."""

    def __init__(self, events: list[dict]):
        self.events = events
        self.findings: list[Finding] = []
        self.stats: dict[str, Any] = {
            "total_events": len(events),
            "events_per_module": Counter(),
            "events_per_type": Counter(),
            "collectors_seen": set(),
        }

    def _add(self, severity: str, check: str, msg: str,
             event_id: str = "", collector: str = ""):
        self.findings.append(Finding(severity, check, msg, event_id, collector))

    # ── Check 1: Envelope compliance ─────────────────────────────────────

    def check_envelope(self):
        """Verify every event has all required envelope fields with correct types."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))

            for key, expected_type in ENVELOPE_REQUIRED.items():
                val = ev.get(key)
                if val is None:
                    self._add("ERROR", "envelope.missing", f"Missing required field '{key}'",
                              eid, mod)
                elif not check_type(val, expected_type):
                    self._add("ERROR", "envelope.type", (
                        f"'{key}' expected {expected_type}, got {type_name(val)} "
                        f"(value: {str(val)[:80]})"), eid, mod)

            # Validate event.kind
            kind = ev.get("event.kind")
            if kind and kind not in VALID_KINDS:
                self._add("WARN", "envelope.kind",
                          f"event.kind='{kind}' not in {VALID_KINDS}", eid, mod)

            # Validate event.category
            cat = ev.get("event.category")
            if cat and cat not in VALID_CATEGORIES:
                self._add("WARN", "envelope.category",
                          f"event.category='{cat}' not in {VALID_CATEGORIES}", eid, mod)

            # Track stats
            self.stats["events_per_module"][mod] += 1
            self.stats["events_per_type"][ev.get("event.type", "?")] += 1
            self.stats["collectors_seen"].add(mod)

    # ── Check 2: Severity range ──────────────────────────────────────────

    def check_severity(self):
        """Validate event.severity is int 0-4."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            sev = ev.get("event.severity")
            if sev is not None:
                if not isinstance(sev, int) or isinstance(sev, bool):
                    self._add("ERROR", "severity.type",
                              f"event.severity should be int, got {type_name(sev)}", eid, mod)
                elif sev < 0 or sev > 4:
                    self._add("ERROR", "severity.range",
                              f"event.severity={sev} out of range [0,4]", eid, mod)

    # ── Check 3: Timestamp sanity ────────────────────────────────────────

    def check_timestamps(self):
        """Validate @timestamp is valid RFC3339 and recent."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            ts = ev.get("@timestamp")
            if ts is None:
                continue  # already caught by envelope check
            ts_str = str(ts)
            if not is_valid_rfc3339(ts_str):
                self._add("ERROR", "timestamp.format",
                          f"@timestamp is not valid RFC3339: '{ts_str}'", eid, mod)
            elif not is_recent_timestamp(ts_str):
                self._add("WARN", "timestamp.stale",
                          f"@timestamp is not recent (>24h old or future): '{ts_str}'", eid, mod)

    # ── Check 4: Per-collector field validation ──────────────────────────

    def check_collector_fields(self):
        """Validate each event's payload against the matching collector spec."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            ev_module = ev.get("event.module", "")
            ev_type = ev.get("event.type", "")
            payload = ev.get("payload")

            if not isinstance(payload, dict):
                continue  # already flagged by envelope check

            # Find matching spec(s)
            matched_specs = [
                s for s in SPECS
                if s.event_module == ev_module and ev_type in s.event_types
            ]

            if not matched_specs:
                # Unknown event type — not necessarily an error
                self._add("INFO", "collector.unknown",
                          f"No spec found for module='{ev_module}' type='{ev_type}'",
                          eid, ev_module)
                continue

            for spec in matched_specs:
                self._validate_against_spec(ev, payload, spec, eid)

    def _validate_against_spec(self, ev: dict, payload: dict,
                                spec: CollectorSpec, eid: str):
        """Validate one event against one collector spec."""
        mod = spec.event_module

        # envelope values
        if ev.get("event.category") != spec.event_category:
            self._add("ERROR", "collector.category",
                      (f"event.category='{ev.get('event.category')}' expected "
                       f"'{spec.event_category}'"), eid, spec.name)

        if ev.get("event.kind") != spec.event_kind:
            self._add("ERROR", "collector.kind",
                      (f"event.kind='{ev.get('event.kind')}' expected "
                       f"'{spec.event_kind}'"), eid, spec.name)

        # severity
        sev = ev.get("event.severity")
        if spec.severity is not None:
            valid_sevs = spec.severity if isinstance(spec.severity, list) else [spec.severity]
            if sev not in valid_sevs:
                self._add("WARN", "collector.severity",
                          f"event.severity={sev} expected one of {valid_sevs}",
                          eid, spec.name)

        # tags
        ev_tags = ev.get("tags") or []
        for tag in spec.tags_must_include:
            if tag not in ev_tags:
                self._add("WARN", "collector.tags",
                          f"Missing expected tag '{tag}'", eid, spec.name)

        # required payload fields
        for field_path, expected_type in spec.required_payload.items():
            val = resolve_nested(payload, field_path)
            if val is None:
                self._add("ERROR", "collector.field.missing",
                          f"Required payload field '{field_path}' is missing",
                          eid, spec.name)
            else:
                if not check_type(val, expected_type):
                    self._add("ERROR", "collector.field.type",
                              (f"Payload '{field_path}' expected {expected_type}, "
                               f"got {type_name(val)} (value: {str(val)[:60]})"),
                              eid, spec.name)
                # Check emptiness for strings
                if expected_type == "str" and is_empty(val):
                    self._add("WARN", "collector.field.empty",
                              f"Required payload field '{field_path}' is empty string",
                              eid, spec.name)

    # ── Check 5: MITRE ATT&CK consistency ────────────────────────────────

    def check_mitre(self):
        """Verify MITRE tactic/technique are set for collectors that require them."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            ev_module = ev.get("event.module", "")
            ev_type = ev.get("event.type", "")

            matched = [
                s for s in SPECS
                if s.event_module == ev_module and ev_type in s.event_types
            ]

            for spec in matched:
                if spec.mitre_tactic:
                    tactic = ev.get("threat.tactic.name", "")
                    if not tactic:
                        self._add("ERROR", "mitre.tactic.missing",
                                  f"Expected threat.tactic.name='{spec.mitre_tactic}'",
                                  eid, spec.name)
                    elif tactic != spec.mitre_tactic:
                        self._add("WARN", "mitre.tactic.mismatch",
                                  (f"threat.tactic.name='{tactic}' expected "
                                   f"'{spec.mitre_tactic}'"), eid, spec.name)

                if spec.mitre_technique:
                    tech = ev.get("threat.technique.id", "")
                    expected = (spec.mitre_technique if isinstance(spec.mitre_technique, list)
                                else [spec.mitre_technique])
                    if not tech:
                        self._add("ERROR", "mitre.technique.missing",
                                  f"Expected threat.technique.id in {expected}",
                                  eid, spec.name)
                    elif tech not in expected:
                        # Also check if it's in the payload (like file access)
                        payload = ev.get("payload", {})
                        payload_tech = resolve_nested(payload, "threat.technique.id")
                        if not payload_tech or (
                            isinstance(payload_tech, list) and
                            not any(t in expected for t in payload_tech)
                        ):
                            self._add("WARN", "mitre.technique.mismatch",
                                      (f"threat.technique.id='{tech}' not in "
                                       f"expected {expected}"), eid, spec.name)

    # ── Check 6: Payload nesting ─────────────────────────────────────────

    def check_nesting(self):
        """Verify payload uses proper nested maps (not flat dot-keys)."""
        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            payload = ev.get("payload")
            if not isinstance(payload, dict):
                continue

            # Check for flat dot-notation keys at the top level of payload
            # (e.g. "process.pid" as a literal key instead of nested {"process":{"pid":...}})
            for key in payload:
                if "." in key:
                    self._add("WARN", "nesting.flat_key",
                              (f"Payload has flat dot-key '{key}' — "
                               "should be a nested object"), eid, mod)

    # ── Check 7: Duplicate envelope fields in payload ────────────────────

    def check_duplicates(self):
        """Flag envelope-level fields that are duplicated inside payload."""
        envelope_keys = {"event.type", "event.category", "event.kind",
                         "event.severity", "event.module"}

        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            payload = ev.get("payload")
            if not isinstance(payload, dict):
                continue

            flat = flatten_dict(payload)
            for ek in envelope_keys:
                if ek in flat:
                    # This is a known issue for IPC — flag it
                    self._add("WARN", "duplicate.envelope_in_payload",
                              (f"Envelope field '{ek}' is also present inside "
                               f"payload (value: {str(flat[ek])[:60]})"), eid, mod)

            # Check for payload.event.category / payload.event.type arrays
            # (IPC collector issue)
            for path in ["event.category", "event.type"]:
                val = resolve_nested(payload, path)
                if val is not None and isinstance(val, list):
                    self._add("WARN", "duplicate.payload_event_array",
                              (f"payload.{path} is an array {val} — "
                               "this duplicates the envelope field"), eid, mod)

    # ── Check 8: Type correctness (numbers vs strings) ───────────────────

    def check_type_correctness(self):
        """Spot-check common type mismatches in payload fields."""
        # Fields that must be numeric (not strings)
        MUST_BE_NUMERIC = {
            "process.pid", "process.ppid", "process.session_id",
            "process.tty", "process.threads.count", "process.fd_count",
            "process.memory.rss", "process.memory.vms",
            "process.io.read_bytes", "process.io.write_bytes",
            "source.port", "destination.port",
            "file.size", "file.uid", "file.gid",
            "network.inode", "dns.id",
            "dll.size",
            "xdr.kernel_module.size", "xdr.kernel_module.ref_count",
        }
        # Fields that must be strings (not numbers)
        MUST_BE_STRING = {
            "process.name", "process.executable", "process.entity_id",
            "process.hash.sha256", "file.hash.sha256", "dll.hash.sha256",
            "network.community_id", "network.transport", "network.type",
            "source.ip", "destination.ip",
            "file.path", "file.name", "file.mode",
            "dns.question.name", "dns.question.type",
            "driver.name",
        }

        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            payload = ev.get("payload")
            if not isinstance(payload, dict):
                continue

            flat = flatten_dict(payload)

            for path in MUST_BE_NUMERIC:
                if path in flat and flat[path] is not None:
                    val = flat[path]
                    if isinstance(val, str):
                        self._add("ERROR", "type.should_be_numeric",
                                  f"'{path}' is a string '{val}' but should be numeric",
                                  eid, mod)
                    elif isinstance(val, bool):
                        self._add("ERROR", "type.should_be_numeric",
                                  f"'{path}' is a bool but should be numeric",
                                  eid, mod)

            for path in MUST_BE_STRING:
                if path in flat and flat[path] is not None:
                    val = flat[path]
                    if not isinstance(val, str):
                        self._add("ERROR", "type.should_be_string",
                                  f"'{path}' is {type_name(val)} but should be string",
                                  eid, mod)

    # ── Check 9: Field completeness ──────────────────────────────────────

    def check_completeness(self):
        """Flag required fields that are present but hold empty/zero values
        when they shouldn't (e.g. process.pid=0, empty hashes, blank paths)."""

        # PID=0 is technically valid (kernel) but suspicious for user processes
        PID_FIELDS = {"process.pid", "process.ppid"}
        HASH_FIELDS = {"process.hash.sha256", "file.hash.sha256", "dll.hash.sha256"}
        PATH_FIELDS = {"process.executable", "file.path", "dll.path"}

        for ev in self.events:
            eid = str(ev.get("id", "?"))
            mod = str(ev.get("event.module", "?"))
            payload = ev.get("payload")
            if not isinstance(payload, dict):
                continue

            flat = flatten_dict(payload)

            # PID = 0 for non-kernel events
            for pf in PID_FIELDS:
                if pf in flat and flat[pf] == 0:
                    ev_type = ev.get("event.type", "")
                    # Process collector: pid=0 is suspicious
                    if "process.start" in ev_type or "process.end" in ev_type:
                        self._add("WARN", "completeness.zero_pid",
                                  f"'{pf}' is 0 in a process event", eid, mod)

            # Empty hash where we expect one
            for hf in HASH_FIELDS:
                if hf in flat and isinstance(flat[hf], str):
                    h = flat[hf]
                    if h == "" or h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                        # SHA-256 of empty file
                        self._add("INFO", "completeness.empty_hash",
                                  f"'{hf}' is empty or hash-of-empty-file", eid, mod)

            # Empty paths
            for pf in PATH_FIELDS:
                if pf in flat and isinstance(flat[pf], str) and flat[pf].strip() == "":
                    self._add("WARN", "completeness.empty_path",
                              f"'{pf}' is empty", eid, mod)

            # agent.id and host.hostname at envelope level
            if is_empty(ev.get("agent.id")):
                self._add("ERROR", "completeness.agent_id",
                          "agent.id is empty", eid, mod)
            if is_empty(ev.get("host.hostname")):
                self._add("ERROR", "completeness.hostname",
                          "host.hostname is empty", eid, mod)

    # ── Check 10: Collector coverage ─────────────────────────────────────

    def check_coverage(self):
        """Verify all 13 collectors have at least one event."""
        seen = self.stats["collectors_seen"]
        for coll in COVERAGE_COLLECTORS:
            if coll not in seen:
                self._add("ERROR", "coverage.missing",
                          f"No events from collector '{coll}'", collector=coll)

    # ── Run all checks ───────────────────────────────────────────────────

    def run_all(self):
        """Execute every validation check."""
        self.check_envelope()
        self.check_severity()
        self.check_timestamps()
        self.check_collector_fields()
        self.check_mitre()
        self.check_nesting()
        self.check_duplicates()
        self.check_type_correctness()
        self.check_completeness()
        self.check_coverage()
        return self

    # ── Reporting ────────────────────────────────────────────────────────

    def print_report(self):
        """Print a human-readable report to stdout."""
        errors = [f for f in self.findings if f.severity == "ERROR"]
        warns = [f for f in self.findings if f.severity == "WARN"]
        infos = [f for f in self.findings if f.severity == "INFO"]

        print()
        print(_c("B", "═" * 70))
        print(_c("B", "  XDR-AGENT TELEMETRY DEEP ANALYSIS REPORT"))
        print(_c("B", "═" * 70))
        print()

        # ── Stats ────────────────────────────────────────────────────────
        print(_c("B", "── Event Statistics ──────────────────────────────────────"))
        print(f"  Total events captured: {self.stats['total_events']}")
        print(f"  Unique collectors seen: {len(self.stats['collectors_seen'])}/{len(COVERAGE_COLLECTORS)}")
        print()
        print("  Events per collector:")
        for mod, count in sorted(self.stats["events_per_module"].items()):
            marker = _c("G", "✓") if mod in COVERAGE_COLLECTORS else " "
            print(f"    {marker} {mod}: {count}")
        print()
        print("  Events per type:")
        for etype, count in sorted(self.stats["events_per_type"].items()):
            print(f"    {etype}: {count}")
        print()

        # ── Coverage ─────────────────────────────────────────────────────
        print(_c("B", "── Collector Coverage ────────────────────────────────────"))
        for coll in COVERAGE_COLLECTORS:
            if coll in self.stats["collectors_seen"]:
                cnt = self.stats["events_per_module"].get(coll, 0)
                print(f"  {_c('G', '✓')} {coll} ({cnt} events)")
            else:
                print(f"  {_c('R', '✗')} {coll} — NO EVENTS")
        print()

        # ── Findings by check ────────────────────────────────────────────
        if errors:
            print(_c("B", f"── Errors ({len(errors)}) ──────────────────────────────────────────"))
            # Deduplicate by (check, message-prefix) to avoid flooding
            seen_msgs: dict[str, int] = {}
            for f in errors:
                key = f"{f.check}:{f.message[:80]}"
                seen_msgs[key] = seen_msgs.get(key, 0) + 1

            printed: set[str] = set()
            for f in errors:
                key = f"{f.check}:{f.message[:80]}"
                if key not in printed:
                    printed.add(key)
                    count = seen_msgs[key]
                    suffix = f" (×{count})" if count > 1 else ""
                    print(f"{f}{suffix}")
            print()

        if warns:
            print(_c("B", f"── Warnings ({len(warns)}) ────────────────────────────────────────"))
            seen_msgs = {}
            for f in warns:
                key = f"{f.check}:{f.message[:80]}"
                seen_msgs[key] = seen_msgs.get(key, 0) + 1

            printed = set()
            for f in warns:
                key = f"{f.check}:{f.message[:80]}"
                if key not in printed:
                    printed.add(key)
                    count = seen_msgs[key]
                    suffix = f" (×{count})" if count > 1 else ""
                    print(f"{f}{suffix}")
            print()

        if infos:
            print(_c("B", f"── Info ({len(infos)}) ─────────────────────────────────────────────"))
            seen_msgs = {}
            for f in infos:
                key = f"{f.check}:{f.message[:80]}"
                seen_msgs[key] = seen_msgs.get(key, 0) + 1

            printed = set()
            for f in infos:
                key = f"{f.check}:{f.message[:80]}"
                if key not in printed:
                    printed.add(key)
                    count = seen_msgs[key]
                    suffix = f" (×{count})" if count > 1 else ""
                    print(f"{f}{suffix}")
            print()

        # ── Summary ──────────────────────────────────────────────────────
        print(_c("B", "── Summary ──────────────────────────────────────────────"))
        cov = len([c for c in COVERAGE_COLLECTORS if c in self.stats["collectors_seen"]])
        total_c = len(COVERAGE_COLLECTORS)
        print(f"  Collectors: {cov}/{total_c}")
        print(f"  Errors:     {len(errors)}")
        print(f"  Warnings:   {len(warns)}")
        print(f"  Info:       {len(infos)}")
        print()

        if len(errors) == 0 and cov == total_c:
            print(_c("G", "═" * 70))
            print(_c("G", f"  ALL {total_c}/{total_c} COLLECTORS VERIFIED — 0 ERRORS ✓"))
            print(_c("G", "═" * 70))
        elif len(errors) == 0:
            print(_c("Y", "═" * 70))
            print(_c("Y", f"  {cov}/{total_c} COLLECTORS — 0 ERRORS, {total_c - cov} MISSING"))
            print(_c("Y", "═" * 70))
        else:
            print(_c("R", "═" * 70))
            print(_c("R", f"  {cov}/{total_c} COLLECTORS — {len(errors)} ERRORS FOUND"))
            print(_c("R", "═" * 70))
        print()

    def write_json_report(self, path: str):
        """Write machine-readable JSON report."""
        cov = len([c for c in COVERAGE_COLLECTORS if c in self.stats["collectors_seen"]])
        report = {
            "version": "0.3.2",
            "total_events": self.stats["total_events"],
            "collectors_seen": sorted(self.stats["collectors_seen"]),
            "collectors_expected": COVERAGE_COLLECTORS,
            "coverage": f"{cov}/{len(COVERAGE_COLLECTORS)}",
            "events_per_module": dict(self.stats["events_per_module"]),
            "events_per_type": dict(self.stats["events_per_type"]),
            "findings": {
                "errors": [f.to_dict() for f in self.findings if f.severity == "ERROR"],
                "warnings": [f.to_dict() for f in self.findings if f.severity == "WARN"],
                "info": [f.to_dict() for f in self.findings if f.severity == "INFO"],
            },
            "summary": {
                "errors": len([f for f in self.findings if f.severity == "ERROR"]),
                "warnings": len([f for f in self.findings if f.severity == "WARN"]),
                "info": len([f for f in self.findings if f.severity == "INFO"]),
                "pass": len([f for f in self.findings if f.severity == "ERROR"]) == 0
                        and cov == len(COVERAGE_COLLECTORS),
            },
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  JSON report written to: {path}")


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <captured_events.json> [--json report.json]",
              file=sys.stderr)
        sys.exit(2)

    events_path = sys.argv[1]
    json_report = None
    if "--json" in sys.argv:
        idx = sys.argv.index("--json")
        if idx + 1 < len(sys.argv):
            json_report = sys.argv[idx + 1]

    # Load events
    with open(events_path) as f:
        events = json.load(f)

    if not isinstance(events, list):
        print("Error: expected a JSON array of events", file=sys.stderr)
        sys.exit(1)

    if len(events) == 0:
        print("Error: no events in file", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    analyzer = TelemetryAnalyzer(events)
    analyzer.run_all()
    analyzer.print_report()

    if json_report:
        analyzer.write_json_report(json_report)

    # Exit code
    errors = len([f for f in analyzer.findings if f.severity == "ERROR"])
    cov = len([c for c in COVERAGE_COLLECTORS if c in analyzer.stats["collectors_seen"]])
    if errors > 0 or cov < len(COVERAGE_COLLECTORS):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
