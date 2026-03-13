#!/usr/bin/env python3
"""
show_samples.py — Print real captured telemetry samples for all 13 collectors.

Each event is displayed with its full envelope (timestamp, event.* fields,
agent.id, host.hostname, tags, threat.*) followed by every payload field,
one field = value per line.

Up to 4 events are shown per collector, selected so that they carry
meaningfully different content (timestamp-only or numeric-only differences
are ignored when picking samples).

Usage:
    sudo python3 test/show_samples.py [capture_file]

If no file is given the script automatically picks the most recent
/tmp/xdr-telemetry-test.*/captured_events.json that contains data.
"""

import json
import os
import sys
import glob
from datetime import datetime

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[36m"
YELLOW  = "\033[33m"
GREEN   = "\033[32m"
RED     = "\033[31m"
GREY    = "\033[90m"
MAGENTA = "\033[35m"
BLUE    = "\033[34m"
WHITE   = "\033[97m"

SEV_COLOUR = {0: GREY, 1: GREEN, 2: YELLOW, 3: RED, 4: "\033[41m"}
SEV_LABEL  = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

# ── Envelope field display order (shown before payload) ───────────────────────
ENVELOPE_FIELDS = [
    "@timestamp",
    "event.type",
    "event.category",
    "event.kind",
    "event.severity",
    "event.module",
    "event.action",
    "agent.id",
    "host.hostname",
    "threat.tactic.name",
    "threat.technique.id",
    "tags",
]

# ── Collector registry (event.module → display label, max samples) ─────────────
COLLECTORS = [
    ("telemetry.process",     "01  Process",          4),
    ("telemetry.fim",         "02  FIM",              4),
    ("telemetry.file.access", "03  File Access",      4),
    ("telemetry.network",     "04  Network",          4),
    ("telemetry.dns",         "05  DNS",              4),
    ("telemetry.session",     "06  Session",          4),
    ("telemetry.system",      "07  System Metrics",   4),
    ("telemetry.system.cpu",  "07b System CPU",       4),
    ("telemetry.library",     "08  Library",          4),
    ("telemetry.kernel",      "09  Kernel Modules",   4),
    ("telemetry.tty",         "10  TTY",              4),
    ("telemetry.scheduled",   "11  Scheduled Tasks",  4),
    ("telemetry.injection",   "12  Injection",        4),
    ("telemetry.ipc",         "13  IPC",              4),
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def find_capture():
    """Return path to the most recent non-empty captured_events.json."""
    candidates = sorted(
        glob.glob("/tmp/xdr-telemetry-test.*/captured_events.json"),
        key=os.path.getmtime,
        reverse=True,
    )
    for path in candidates:
        try:
            if os.path.getsize(path) > 100:
                return path
        except OSError:
            pass
    return None


def load_events(path):
    with open(path) as f:
        return json.load(f)


def flatten(d, prefix=""):
    """Recursively flatten nested dict to dot-notation keys."""
    out = {}
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten(v, full))
        else:
            out[full] = v
    return out


def fmt_value(v, max_len=140):
    """Format a value as a single-line string, truncating if needed."""
    if v is None:
        s = "null"
    elif isinstance(v, bool):
        s = str(v).lower()
    elif isinstance(v, list):
        s = json.dumps(v, separators=(",", ":"))
    elif isinstance(v, dict):
        s = json.dumps(v, separators=(",", ":"))
    else:
        s = str(v)
    if len(s) > max_len:
        s = s[:max_len] + GREY + "…" + RESET
    return s


def content_fingerprint(ev):
    """Build a frozenset of (key, str-value) pairs ignoring timestamps and
    pure-numeric values.  Used to detect events with meaningfully different
    content."""
    pairs = set()
    # envelope string fields
    for field in ENVELOPE_FIELDS:
        if field in ("@timestamp",):
            continue
        v = ev.get(field)
        if v is None:
            continue
        if isinstance(v, (int, float)):
            continue        # ignore numeric-only differences
        pairs.add((field, json.dumps(v, sort_keys=True)))
    # payload string fields
    pay = flatten(ev.get("payload") or {})
    for k, v in pay.items():
        if isinstance(v, (int, float)):
            continue        # ignore numeric-only differences
        pairs.add((k, json.dumps(v, sort_keys=True)))
    return frozenset(pairs)


def pick_diverse_samples(evts, max_n):
    """Return up to max_n events that are content-diverse.
    Strategy:
      1. One per unique event.type (preserves type variety).
      2. Then add more events whose fingerprint differs from all already picked.
    """
    # Group by event.type
    by_type = {}
    for e in evts:
        t = e.get("event.type", "?")
        by_type.setdefault(t, []).append(e)

    selected = []
    fingerprints = []

    def add(e):
        fp = content_fingerprint(e)
        selected.append(e)
        fingerprints.append(fp)

    # First pass: one per type
    for t, group in by_type.items():
        if len(selected) >= max_n:
            break
        add(group[0])

    # Second pass: fill remaining slots with events that differ from all picked
    for e in evts:
        if len(selected) >= max_n:
            break
        if e in selected:
            continue
        fp = content_fingerprint(e)
        if all(fp != existing for existing in fingerprints):
            add(e)

    return selected[:max_n]


def print_separator(char="─", width=68):
    print(f"  {GREY}{char * width}{RESET}")


def print_field(label, raw_value, label_colour=CYAN, value_colour=WHITE):
    vstr = fmt_value(raw_value)
    print(f"  {GREY}│{RESET}  {label_colour}{label}{RESET} = {value_colour}{vstr}{RESET}")


def print_event(ev, n, total):
    """Print one event: envelope fields then payload fields, one per line."""
    # ── header line ──────────────────────────────────────────────────────────
    sev    = ev.get("event.severity", 0)
    sc     = SEV_COLOUR.get(sev, GREY)
    sl     = SEV_LABEL.get(sev, str(sev))
    etype  = ev.get("event.type", "?")
    ts_raw = ev.get("@timestamp", "")
    ts     = ts_raw[:23].replace("T", " ") if ts_raw else ""

    print(f"  {GREY}┌─ event {n}/{total} {'─'*57}{RESET}")
    print(f"  {GREY}│{RESET}  {BOLD}{WHITE}{etype}{RESET}  "
          f"{sc}{BOLD}[{sl}]{RESET}  {GREY}{ts}{RESET}")
    print(f"  {GREY}│{RESET}")

    # ── envelope section ─────────────────────────────────────────────────────
    print(f"  {GREY}│  {YELLOW}─ envelope ─{RESET}")
    for field in ENVELOPE_FIELDS:
        v = ev.get(field)
        if v is None:
            continue
        if field == "event.severity":
            # show numeric value + label together
            print_field(field, f"{v}  ({sl})", label_colour=CYAN, value_colour=sc)
        else:
            print_field(field, v)

    # ── payload section ───────────────────────────────────────────────────────
    pay_raw = ev.get("payload")
    if pay_raw:
        pay = flatten(pay_raw)
        if pay:
            print(f"  {GREY}│{RESET}")
            print(f"  {GREY}│  {YELLOW}─ payload ─{RESET}")
            for k in sorted(pay.keys()):
                print_field(k, pay[k], label_colour=CYAN, value_colour=GREEN)

    print(f"  {GREY}└{'─'*68}{RESET}")
    print()


def main():
    cap_file = sys.argv[1] if len(sys.argv) > 1 else None
    if not cap_file:
        cap_file = find_capture()
    if not cap_file:
        print(RED + "No capture file found." + RESET)
        print("Run:  sudo KEEP_LOGS=1 bash test/telemetry_verify.sh")
        sys.exit(1)

    mtime  = datetime.fromtimestamp(os.path.getmtime(cap_file)).strftime("%Y-%m-%d %H:%M:%S")
    events = load_events(cap_file)

    print()
    print(f"{BOLD}{BLUE}{'═'*72}{RESET}")
    print(f"{BOLD}{BLUE}  xdr-agent  ·  Real Telemetry Samples  ·  {len(events)} events{RESET}")
    print(f"{BOLD}{BLUE}  Source : {cap_file}{RESET}")
    print(f"{BOLD}{BLUE}  Capture: {mtime}{RESET}")
    print(f"{BOLD}{BLUE}{'═'*72}{RESET}")

    # Group events by module
    by_module: dict = {}
    for e in events:
        m = e.get("event.module", "?")
        by_module.setdefault(m, []).append(e)

    for module, label, max_samples in COLLECTORS:
        evts  = by_module.get(module, [])
        count = len(evts)

        print()
        print(f"{BOLD}{YELLOW}{'─'*72}{RESET}")
        print(f"{BOLD}{YELLOW}  Collector {label}  ({count} events){RESET}")
        print(f"{BOLD}{YELLOW}{'─'*72}{RESET}")

        if not evts:
            print(f"  {RED}✗  No events captured for this module.{RESET}")
            continue

        # Type distribution summary
        type_counts: dict = {}
        for e in evts:
            t = e.get("event.type", "?")
            type_counts[t] = type_counts.get(t, 0) + 1
        dist = "  ".join(
            f"{CYAN}{t}{RESET}×{c}"
            for t, c in sorted(type_counts.items(), key=lambda x: -x[1])
        )
        print(f"  {GREY}types: {dist}{RESET}")
        print()

        samples = pick_diverse_samples(evts, max_samples)
        for i, ev in enumerate(samples, 1):
            print_event(ev, i, len(samples))

    print(f"{BOLD}{BLUE}{'═'*72}{RESET}")
    print(f"{BOLD}{GREEN}  All collectors shown.  Source: real agent telemetry.{RESET}")
    print(f"{BOLD}{BLUE}{'═'*72}{RESET}")
    print()


if __name__ == "__main__":
    main()
