# Telemetry sources and fields

This describes the running collectors, not every entry Linux exposes. Only the sources below are read.

Payload paths below are relative to `payload`; braces list sibling fields. Collector payloads use nested objects (`"process":{"pid":123}`). Envelope names such as `event.type` are literal dotted JSON keys. Protection payloads also use literal dotted keys (`"process.pid":123`).

## Event envelope

[`internal/events/event.go`](../internal/events/event.go) defines all emitted events:

| Field | Meaning |
| --- | --- |
| `id` | Event identifier, retained on delivery retries |
| `@timestamp` | UTC time the Agent observed/emitted the event; not necessarily the kernel action time |
| `event.type` | Observed action, such as `process.start` or `file.modified` |
| `event.category` | Domain, such as process, file, network, threat, prevention, or agent |
| `event.module` | Producing component, such as `telemetry.process` or `detection.malware` |
| `event.kind` | Active producers emit `event` or `alert`; schema also permits `metric`/`state` |
| `event.severity` | Producer-assigned importance: 0 info, 1 low, 2 medium, 3 high, 4 critical; not a process risk score |
| `agent.id` | Persistent identifier of the enrolled Agent |
| `host.hostname` | Host name associated with the event |
| `payload` | Producer-specific objects and values described below |
| `tags` | Optional labels for filtering; process events use `process`, `telemetry` |
| `threat.tactic.name` | Optional ATT&CK tactic; file-access events use `Credential Access` |
| `threat.technique.id` | Optional ATT&CK technique/subtechnique identifier assigned by the producer |
| `threat.technique.subtechnique.id` | Optional separate subtechnique field; no active producer populates it |

`event.severity` is required by the shared event schema. Process, connection, and DNS telemetry always use `0`; no current path raises their severity. A YARA match emits a separate severity-`3` security alert and leaves the source telemetry unchanged. File telemetry can use 1–3 even without a confirmed threat. Routing to telemetry/security uses event kind/module, not severity; `0` does not certify that an activity is safe.

## Processes

[`monitor.go`](../internal/telemetry/process/monitor.go) and [`enrichment.go`](../internal/telemetry/process/enrichment.go) scan numeric `/proc/<PID>/` directories on the [configured interval](architecture.md#runtime-and-configuration). The first scan establishes a silent baseline. Later PID-set differences emit `process.start` / `process.end`, module `telemetry.process`, category `process`, kind `event`, severity `0`.

Each row describes one emitted value. Sources without a leading `/` are relative to `/proc/<PID>/`. **Local use** identifies current Agent behavior; investigation fields are shipped for analysis and do not drive active behavioral rules.

| Payload field | Source | Meaning / format | Purpose |
| --- | --- | --- | --- |
| `process.pid` | Numeric directory name | Process ID; reusable after exit | Snapshot comparison, executable scan, termination target |
| `process.ppid` | `stat` field 4 | Parent process ID | Build process lineage |
| `process.entity_id` | Host name + PID + start ticks | First 16 hex characters of SHA-256 of `hostname-pid-starttime`; process-instance correlation key | Link related process records; lacks boot/Agent identity |
| `process.name` | `stat` field 2 (`comm`) | Short task name; may differ from executable/arguments and can be changed | Investigation label |
| `process.executable` | `exe` symlink | Resolved executable path; interpreted commands usually identify the interpreter | Select executable for YARA; identify related processes |
| `process.command_line` | `cmdline` | Arguments joined with spaces; original argument boundaries are lost | Readable execution context |
| `process.args` | Separate `cmdline` read | Array preserving nonempty NUL-separated arguments; unavailable/empty becomes `null` | Structured execution context |
| `process.working_directory` | `cwd` symlink | Process working-directory path; `""` when unresolved | Resolve execution context; target is not traversed |
| `process.state` | `stat` field 3 | Kernel state, e.g. R running, S sleeping, D uninterruptible wait, Z zombie, T/t stopped/traced, I idle | Snapshot context |
| `process.start_time` | `stat` field 22 | Clock ticks since boot, not a UTC timestamp | Derive entity ID; verify process before termination |
| `process.session_id` | `stat` field 6 | Session ID, normally the session leader's PID; not the audit login session ID | Look up the reported group leader |
| `process.tty.nr` | `stat` field 7 | Encoded controlling-terminal device number; 0 means none when read successfully | Interactive-session context |
| `process.user.id` | `status`: first `Uid` value | Real user ID as an integer | Ownership context |
| `process.user.name` | `/etc/passwd`, cached | Login name corresponding to the real UID; empty if unresolved | Readable ownership label |
| `process.group.id` | `status`: first `Gid` value | Real group ID as an integer | Ownership context |
| `process.group.name` | `/etc/group`, cached | Group name corresponding to the real GID; empty if unresolved | Readable group label |
| `process.effective_user.id` | `status`: second `Uid` value | Effective user ID; can differ from the real UID | Privilege context |
| `process.effective_group.id` | `status`: second `Gid` value | Effective group ID; supplementary groups are not collected | Privilege context |
| `process.cap_eff` | `status`: `CapEff` | Hexadecimal effective Linux-capability bitmask, not decoded capability names | Privilege context; not an automatic alert |
| `process.threads.count` | `status`: `Threads` | Number of threads in the process | Resource context |
| `process.fd_count` | Count of `fd/` entries | Number of open file descriptors, or 0 on read failure | Resource context; socket ownership is resolved separately |
| `process.memory.rss` | `status`: `VmRSS` | Resident memory in bytes (reported kB × 1024) | Resource context |
| `process.memory.vms` | `status`: `VmSize` | Virtual address-space size in bytes (kB × 1024); not physical RAM use | Resource context |
| `process.io.read_bytes` | `io`: `read_bytes` | Cumulative storage-read byte counter, not a rate or network traffic | Resource context |
| `process.io.write_bytes` | `io`: `write_bytes` | Cumulative storage-write byte counter, not a rate | Resource context |
| `process.cpu.pct` | Deltas of `stat` fields 14/15 and `/proc/stat` | Optional percentage of total host CPU capacity, rounded to 2 decimals | Retain last measured nonzero value for end events |
| `container.id` | `cgroup` | First 12 characters of a recognized Docker/containerd/Kubernetes/Podman ID; omitted if undetected | Container correlation; not complete container metadata |

[`tree.go`](../internal/telemetry/process/tree.go) adds relationship objects. Their child fields have the same meanings as the corresponding process fields above, applied to the related process:

| Payload object | Included child fields | Meaning / limits |
| --- | --- | --- |
| `process.parent` | `pid`, `ppid`, `entity_id`, `name`, `executable`, `command_line`, `args` | Direct parent's last known context; its `ppid` is the child's grandparent. `{}` when unresolved |
| `process.ancestors[]` | `pid`, `ppid`, `entity_id`, `name`, `executable` | Up to 10 known ancestors ordered from direct parent toward root; `[]` when unavailable |
| `process.group_leader` | `pid`, `name`, `entity_id` | Current implementation looks up the session leader using `session_id`; it does not collect the actual process-group ID. `{}` when unresolved |

CPU uses `100 × Δ(utime+stime)/Δsystem ticks`. Only the first aggregate `cpu` line of `/proc/stat` is read, summing all numeric columns; per-CPU lines, `intr`, `btime`, and `ctxt` are unused. Raw CPU ticks are used internally but not emitted. `/proc/uptime` is not read.

Values refresh each scan but are shipped only with lifecycle events. Start events omit CPU percentage; end events carry the last snapshot and last retained percentage ≥0.01%, which may predate the last interval. There is no continuous resource stream or exit code. Event time records discovery/disappearance, not exact execution/exit time.

Unreadable `stat` skips the PID. Other read failures leave empty strings, `null`, or numeric zeros; a zero UID does not establish root ownership, and zero I/O/FD counts do not establish inactivity. Command line and argument reads can disagree if the process changes/exits between reads. The payload has no per-field collection-success flags. Polling and PID-only comparisons can miss short-lived processes, PID reuse, and exec changes within an existing PID.

## Connections and DNS

[`connections.go`](../internal/telemetry/network/connections.go) reads only `/proc/net/{tcp,tcp6,udp,udp6}`: local/remote address and port, state, UID, inode. It emits `network.connection_opened` / `network.connection_closed`, module `telemetry.network`, category `network`, severity 0, after a silent first baseline.

| Payload field(s) | Meaning / source |
| --- | --- |
| `source.ip`, `source.port` | Local socket IP address and port, including inbound connections |
| `destination.ip`, `destination.port` | Remote socket IP address and port |
| `source.user.id`, `source.user.name` | Socket-owning UID as a string and its resolved user name |
| `network.transport`, `network.type` | Protocol (`tcp`/`udp`) and address family (`ipv4`/`ipv6`) |
| `network.state` | Kernel socket state mapped to a TCP state name or raw hex; the same mapping is also used for UDP |
| `network.inode` | Socket inode number used to locate its owner through `/proc/<PID>/fd/*` links |
| `network.community_id` | Direction-independent Community ID v1 hash of the flow endpoints/protocol |
| `network.direction` | Heuristic: listening, internal, inbound, outbound; not proof of initiator |
| `process.pid`, `process.name`, `process.executable` | Optional owning PID, short name from `comm`, and `exe` path; opened events only |

The snapshot key includes protocol, endpoints, and state; a TCP state transition can emit a closed/opened pair. Polling can miss connections; attribution can race with socket closure. Network tables reflect the Agent's network namespace; it does not walk `/proc/<PID>/net` or container namespaces. All other `/proc/net` entries are unused.

[`dns.go`](../internal/telemetry/network/dns.go) captures Ethernet IPv4/IPv6 UDP traffic to/from port 53 on all interfaces through `AF_PACKET` (`CAP_NET_RAW` required). It emits `dns.query` / `dns.answer`, module `telemetry.dns`, category `network`, severity 0.

| Payload field(s) | Meaning / source |
| --- | --- |
| `dns.id`, `dns.type` | 16-bit transaction ID and message role (`query`/`answer`) |
| `dns.op_code` | Requested DNS operation, usually `QUERY` |
| `dns.question.name` | First queried domain name |
| `dns.question.type`, `dns.question.class` | Requested record type (e.g. A/AAAA) and DNS class (usually IN) |
| `dns.question.registered_domain` | Last two labels of the question name; not public-suffix aware |
| `dns.recursion_desired`, `dns.recursion_available` | Header booleans: client requests recursion (RD); server advertises it (RA) |
| `dns.authoritative` | Header AA flag: response claims to be authoritative |
| `dns.header_flags` | Active flags: qr response, aa authoritative, tc truncated, rd recursion desired, ra recursion available |
| `dns.response_code` | Response outcome such as NOERROR/NXDOMAIN; responses only |
| `dns.answers_count` | Number of parsed/emitted answers, capped at 64; omitted without answers |
| `dns.answers[].name`, `dns.answers[].type` | Answer record's owner domain and record type |
| `dns.answers[].ttl`, `dns.answers[].data` | Cache lifetime in seconds and decoded record content (hex fallback for unsupported types) |
| `dns.resolved_ips` | IP values from A/AAAA answers; omitted when none |
| `source.{ip,port}`, `destination.{ip,port}` | Packet source/destination addresses and ports; responses reverse client/resolver direction |
| `network.{transport,type,community_id}` | UDP, IPv4/IPv6, and the flow hash defined above |
| `process.{pid,name,executable}` | Optional querying-process identity; UDP socket ownership snapshots cached for 2 s and query-response correlation |

No TCP DNS, DoH/DoT, raw packet payload, authority/additional records, or full packet capture is shipped. Process attribution uses `/proc/net/udp{,6}` and PID socket links/`comm`/`exe` and is best effort.

## File changes and access

[`paths.go`](../internal/telemetry/file/paths.go) defines the fixed integrity watch list. Recursive directories: `/etc/{sudoers.d,pam.d,security,ssh,cron.d,cron.daily,cron.hourly,cron.weekly,cron.monthly,systemd/system,ld.so.conf.d,profile.d,modprobe.d,modules-load.d,apparmor.d}`, `/root/.ssh`, `/etc/apt/{sources.list.d,apt.conf.d,trusted.gpg.d}`, `/var/spool/cron/crontabs`.

Direct files: `/etc/{passwd,shadow,group,gshadow,security/opasswd,sudoers,crontab,ld.so.conf,ld.so.preload,profile,environment,default/grub,hosts,hostname,resolv.conf,nsswitch.conf,hosts.allow,hosts.deny,fstab,bash.bashrc,apt/sources.list}`, `/root/{.bashrc,.profile,.bash_login}`, `/boot/grub/grub.cfg`. Nonrecursive directories (immediate files only): `/usr/lib/systemd/system`, `/lib/systemd/system`, `/boot/grub`, `/lib/{x86_64-linux-gnu,aarch64-linux-gnu}/security`, `/usr/share/keyrings`. Missing paths are skipped; this is not a whole-filesystem baseline.

[`fim.go`](../internal/telemetry/file/fim.go) uses inotify plus hourly rescans against a persistent BoltDB baseline. Initial baseline emits no events; warm restarts retain existing records. New subdirectories of recursive watches are added. Renames are delete/create events; inotify overflow schedules a rescan. Individually watched files can lose their watch after replacement; rescans still compare their paths.

| Payload field(s) | Meaning / local use |
| --- | --- |
| `file.path`, `file.name`, `file.directory` | Full path, basename, and parent directory |
| `file.type` | File kind, normally `file` or `symlink`; targets are not followed for hashing |
| `file.uid`, `file.gid` | Numeric owning user/group IDs |
| `file.owner`, `file.group` | Resolved owner/group names; omitted if lookup fails |
| `file.mode` | Octal rwx permission bits only (0000–0777); setuid/setgid/sticky bits are not collected or compared |
| `file.size` | Size in bytes; omitted when zero |
| `file.mtime`, `file.ctime` | Content-modification time and inode-change time, UTC strings with whole-second precision |
| `file.hash.sha256` | Content SHA-256 hex digest; used to detect content changes |
| `file.entropy` | Shannon entropy in bits/byte (0–8); >7.5 raises severity/tags |
| `file.header_bytes` | Base64-encoded first ≤256 bytes; content is shipped, not just a fingerprint |
| `fim.action` | Normalized change: created, modified, attributes_modified, deleted |
| `fim.previous.{hash.sha256,size,mode,uid,gid}` | Only changed old hash, size, permissions, owner ID, and group ID, with the same formats as current values |

Events are `file.created`, `file.modified`, `file.attrs_changed`, `file.deleted`, module `telemetry.file`, category `file`, kind `event`. Hash, entropy, and header fields require a readable regular file ≤256 MiB; empty/zero optional values may be omitted.

Hash and permission/ownership changes drive rescan events. Creates are severity 2; attribute changes are 1 (inotify) or 2 (rescan). Modifications/deletions are 2, or 3 on critical paths. Entropy >7.5 raises severity to at least 3 and adds `high-entropy` / `potentially-packed` tags; it is not itself a YARA match. Deleted events can contain last-known metadata. Symlinks are recorded without hashing their target; files above the size limit have no content hash.

[`access.go`](../internal/telemetry/file/access.go) watches `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd` for open/read, and `/root/.ssh`, `/etc/ssh` for immediate-child opens. Emits `file.access`, module `telemetry.file`, category `file`, severity 3. `file.{path,name,directory}` identify the accessed file; `file.event.action=access` and `event.action=file-accessed` label the action inside the payload. ATT&CK mapping is Credential Access / T1003.008 (password files) or T1552.004 (SSH paths), based on path rather than a confirmed attack. Legitimate reads, including the Agent's own, can trigger events; inotify provides no accessing PID/user. Watches are installed once, not recursively; missing/replaced paths need restart to reinstall. At most one event/path/2 s and 200 events/s are emitted. Health is separately reported as `telemetry.file.access`; running health does not guarantee every optional watch succeeded.

## Protection and runtime logs

| Producer / event | Behavior |
| --- | --- |
| `detection.malware` / `alert` | YARA consumes `process.executable` + PID (`/proc/<PID>/exe`) or `file.path`; emits matching rules and copied process context. Category threat, kind alert, severity 3 |
| `prevention.manager` / `prevention.action` | Checks YARA method, deny-request flag, PID/start ticks and executable identity before termination |
| `prevention.execution` / `prevention.action` | Reports fanotify execution-denial decisions or response failures |
| `agent.logger` / `agent.log` | Captures the Agent's standard logger; shipper diagnostics stay local to avoid feedback loops |

Protection payload names below are literal dotted keys, except `action`, `detail`, and `method`:

| Payload field(s) | Meaning |
| --- | --- |
| `rule.id`, `rule.name` | First matching YARA rule identifier; both currently contain the same name |
| `rule.names` | Array of all matching rule identifiers |
| `method` | Detection method, currently `yara` |
| `file.path` | Scanned file/executable path |
| `file.device`, `file.inode` | Filesystem device and inode numbers of the matched file |
| `file.size`, `file.mtime_ns` | Matched file size in bytes and modification time as Unix nanoseconds; used with device/inode to verify identity before termination |
| `process.*` | Copied source-process fields with the meanings above; execution events may carry only `process.pid` |
| `execution.deny_requested` | Boolean: the match requested denial; does not confirm successful enforcement |
| `source.event.id` | Malware alert: originating telemetry ID, empty for execution-triggered scans. Manager outcome: originating alert ID |
| `action` | Manager: alert_only, process_killed, kill_skipped. Execution guard: execution_denied, execution_response_failed |
| `detail` | Manager's skip/error explanation; empty if there is none |

Logs send `message` (diagnostic text) and literal `log.level` (INFO/WARN/ERROR inferred from message text). Logs and execution outcomes do not carry all malware-alert fields; file-only manager outcomes may have a null `process.pid`.

Prevention events use category `prevention`, kind `event`, severity 3. Logs use category `agent`, kind `event`, and severity 0/2/3 for INFO/WARN/ERROR.

Protection also reads `status:PPid` and `/proc/self/fd/*` to recognize its own scanner helpers and identify open executables; YARA receives the file as `/proc/self/fd/3`. `/proc/self/task/` lists Agent threads for CPU affinity. These are operational reads, not additional telemetry collectors. Most other fields provide investigation context; the active engine does not apply behavioral rules to command lines, ancestry, DNS, or connections.

## Coverage and sensitive data

The Agent does not read process `environ`, `mem`, `maps`, `smaps`, `fdinfo`, `mountinfo`, `ns`, `statm`, or arbitrary `/proc` entries. It does not collect general system/application logs, terminal input, full file contents as telemetry, or process executable hashes. YARA reads executable/file bytes locally. File header bytes, command lines/arguments, usernames, paths, DNS names/answers, and diagnostic text are shipped without a general redaction layer. File headers can include credential material. Remote retention is owned by the destination. Delivery loss and protection limits are in [architecture](architecture.md).

Collection review priorities, **not implemented changes**:

- Keep executable/identity, lineage, user and capability context. `args` preserves argument boundaries while `command_line` aids display; resource snapshots have lower security value and are candidates for optional collection.
- `file.header_bytes` is the strongest candidate for removal or opt-in: it can expose credentials and is not consumed by the active local YARA engine. Review command-line redaction alongside it.
- Add collection-success indicators before treating empty/zero values as facts. File setuid/setgid/sticky bits and boot-aware process identity are useful gaps: current `file.mode` excludes those bits, and `entity_id` can repeat across boots or hosts with reused names. More fields alone will not fix missed executions from polling.
