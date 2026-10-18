# Telemetry sources and fields

This describes the running collectors, not every entry Linux exposes. Only the sources below are read.

All fields are at the document root; braces list sibling fields. Collector details use nested objects (`"process":{"pid":123}`). Envelope names such as `event.type` and protection details such as `process.pid` are literal dotted JSON keys.

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
| `event.severity` | Present for file telemetry, security events, and runtime logs: 0 info, 1 low, 2 medium, 3 high, 4 critical |
| `agent.id` | Persistent identifier of the enrolled Agent |
| `host.hostname` | Host name associated with the event |
| `tags` | Optional labels for filtering; process events use `process`, `telemetry` |
| `threat.tactic.name` | Optional ATT&CK tactic; file-access events use `Credential Access` |
| `threat.technique.id` | Optional ATT&CK technique/subtechnique identifier assigned by the producer |
| `threat.technique.subtechnique.id` | Optional separate subtechnique field; no active producer populates it |

Process, connection, and DNS telemetry omit `event.severity`. File telemetry uses 1–3; YARA matches produce separate severity-3 security alerts. Routing uses event kind/module, not severity.

Collection timing and [batch delivery](architecture.md#event-delivery-and-loss) are independent. Coordinator [policy settings](api-endpoints.md#managed-configuration) update scan/send intervals and internal CIDRs in the active local config without restarting collection. Events retain their observation timestamps and IDs while buffered and retried; duplicate IDs already queued or in flight are ignored. Unchanged process/socket/file snapshots do not generate new events. Distinct occurrences retain distinct IDs even when their payloads match.

## Processes

[`monitor.go`](../internal/telemetry/process/monitor.go) and [`enrichment.go`](../internal/telemetry/process/enrichment.go) scan numeric `/proc/<PID>/` directories on `process_scan_interval_seconds` (default 1 s), independently of shipping. The first scan establishes a silent baseline. Later PID + start-tick differences emit `process.start` / `process.end` once per observed transition, including PID reuse. Module `telemetry.process`, category `process`, kind `event`.

The table describes collected fields. Sources without a leading / are relative to /proc/<PID>/. Usage explains each field’s purpose in Agent operation or security investigations.

| Field | Source | Meaning / format | Usage |
| --- | --- | --- | --- |
| `process.pid` | Numeric directory name | Process ID; reusable after exit | Snapshot comparison, executable scan, termination target |
| `process.ppid` | `stat` field 4 | Parent process ID | Build process lineage |
| `process.entity_id` | Agent ID + PID + start ticks | Full 64-character hex SHA-256 of `agent_id-pid-starttime`; process-instance correlation key | Link process, parent, ancestor, and session-leader records within the Agent |
| `process.name` | `stat` field 2 (`comm`) | Short task name; may differ from executable/arguments and can be changed | Investigation label |
| `process.executable` | `exe` symlink | Resolved executable path; interpreted commands usually identify the interpreter | Select executable for YARA; identify related processes |
| `process.command_line` | `cmdline` | Arguments joined with spaces; original argument boundaries are lost | Readable execution context |
| `process.args` | Same `cmdline` read as `command_line` | Array preserving nonempty NUL-separated arguments; unavailable/empty becomes `null` | Structured execution context |
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
| `container.id` | `cgroup` | Full recognized Docker/containerd/Kubernetes/Podman ID, excluding cgroup path and runtime scope wrappers; omitted if undetected | Container correlation; not complete container metadata |

[`tree.go`](../internal/telemetry/process/tree.go) adds relationship objects. Their child fields have the same meanings as the corresponding process fields above, applied to the related process:

| Object | Included child fields | Meaning / limits |
| --- | --- | --- |
| `process.parent` | `pid`, `ppid`, `entity_id`, `name`, `executable`, `command_line`, `args` | Direct parent's last known context; its `ppid` is the child's grandparent. Kernel parents have stat-derived identity only, with empty executable/command line and null arguments. `{}` when unresolved |
| `process.ancestors[]` | `pid`, `ppid`, `entity_id`, `name`, `executable` | Up to 10 known ancestors ordered from direct parent toward root; `[]` when unavailable |
| `process.group_leader` | `pid`, `name`, `entity_id` | Current implementation looks up the session leader using `session_id`; it does not collect the actual process-group ID. `{}` when unresolved |

Notes:

- Kernel threads are identified by `PF_KTHREAD` in `stat` field 9. These are not sent in any emitted field. Kernel threads retain only stat-derived metadata locally for lineage; status, arguments, file descriptors, I/O, and container enrichment are skipped, and no kernel-thread start/end events are emitted. User-space descendants and file/network collection remain eligible for collection. E.g. field 9 value `69238848` (`0x04208040`) implies `PF_KTHREAD`: `0x04208040 & 0x00200000 = 0x00200000`.

- CPU uses `100 × Δ(utime+stime)/Δsystem ticks`. Only the first aggregate `cpu` line of `/proc/stat` is read, summing all numeric columns; per-CPU lines, `intr`, `btime`, and `ctxt` are unused. Raw CPU ticks are used internally but not emitted. `/proc/uptime` is not read.

- Values refresh each scan but are shipped only with lifecycle events. Start events omit CPU percentage; end events carry the last snapshot and last retained percentage ≥0.01%, which may predate the last interval. There is no continuous resource stream or exit code. Event time records discovery/disappearance, not exact execution/exit time.

- Unreadable `stat` skips the PID. Other read failures leave empty strings, `null`, or numeric zeros; a zero UID does not establish root ownership, and zero I/O/FD counts do not establish inactivity. Events have no per-field collection-success flags. Polling can miss short-lived processes and exec changes within an existing process instance.

## Connections and DNS

Connections and DNS use separate modules because socket changes and DNS messages are different observations. Both use `event.category=network` and the same telemetry stream. `network.community_id` links observations of the same flow; it is not a unique DNS-transaction ID.

Fields below are at the document root. **Usage** explains each field's role in attribution, correlation, or investigation; these collectors do not apply behavioral detection rules.

[`snapshot.go`](../internal/telemetry/network/snapshot.go) reads each `/proc/net/{tcp,tcp6,udp,udp6}` table once per collection cycle: local/remote address and port, state, UID, inode. The immutable snapshot is shared by connections and DNS; ownership resolution walks `/proc/<PID>/fd/*` at most once per generation, only when needed. DNS never triggers another table read. `network_scan_interval_seconds` defaults to 1 s and is independent of shipment timing.

[`connections.go`](../internal/telemetry/network/connections.go) uses module `telemetry.network`, category `network`. After a silent first baseline, `network.connection_opened` means a socket first appears in a subsequent snapshot; `network.connection_state_changed` means its observed state changes; `network.connection_closed` means it disappears from a successfully read table. These are polling observations, not exact handshake/close timestamps: a socket can first appear in `TIME_WAIT`, and closure events retain its last observed `network.state`. Unchanged snapshots emit nothing. Known process identity and handshake direction are retained for later state/closure events.

`internal_networks` in `/etc/xdr-agent/config.json` defaults to RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 ULA (`fc00::/7`, RFC 4193). A configured list replaces these CIDRs; `[]` clears them. Loopback and exact IPs assigned to host interfaces are always inside, including public IPv4/IPv6 addresses; their surrounding subnets are not automatically included. A shared in-memory address cache reads the local kernel at startup, follows IPv4/IPv6 address-change notifications, and resyncs every minute (also the fallback when notifications are unavailable). No internet requests or config-file rewrites are needed. Discovery uses the Agent's network namespace and cannot discover a router's NAT public IP unless assigned locally or configured explicitly.

Direction is `internal` when both endpoints are inside, `external` when both are outside, `outbound` for inside-to-outside, and `inbound` for outside-to-inside. Unspecified/invalid endpoints are `unknown`. Crossing connection direction requires observed `SYN_SENT`/`SYN_RECV` evidence; otherwise it is `unknown`. Address changes reclassify affected sockets without discarding unrelated handshake evidence or emitting duplicate events. Ports do not establish direction. DNS direction follows packet sender/recipient, so responses can reverse it. `network.state` uses the kernel-state mapping below.

Field numbers count whitespace-separated data columns from 1, including `sl`; combined values such as `IP:port` count as one field.

| Field | Source | Meaning / format | Usage |
| --- | --- | --- | --- |
| `local.ip` | Field 2 (`local_address`), before `:` | Local socket IP, including inbound connections | Identify the local endpoint |
| `local.port` | Field 2 (`local_address`), after `:` | Local socket port as an integer | Identify the local service/client socket |
| `local.user.id` | Field 8 (`uid`) | Socket-owning user ID as a string | Attribute socket ownership |
| `local.user.name` | Field 8 (UID), resolved via system user database or `/etc/passwd` | Resolved user name; numeric UID string if unresolved | Readable ownership label |
| `remote.ip` | Field 3 (`rem_address`), before `:` | Remote socket IP | Identify the peer |
| `remote.port` | Field 3 (`rem_address`), after `:` | Remote socket port as an integer | Identify the peer service/client socket |
| `network.transport` | Network table filename; no data field | `tcp` or `udp` | Group by transport protocol |
| `network.type` | Network table filename; no data field | `ipv4` or `ipv6`; determined by the table, not the printed IP string | Identify address family |
| `network.state` | Field 4 (`st`) | Mapped TCP state name or raw hex; mapping also applies to UDP | Describe socket state; UDP `ESTABLISHED` does not imply a TCP handshake |
| `network.inode` | Field 10 (`inode`) | Kernel socket inode; 0 when unavailable | Locate ownership through `/proc/<PID>/fd/*` links |
| `network.community_id` | Derived from fields 2/3 and filename (protocol) | Direction-independent Community ID v1 flow hash | Correlate observations across collectors |
| `network.direction` | Fields 2/3/4, configured `internal_networks`, and kernel interface addresses | Perimeter classification: internal, external, inbound, outbound, unknown | Orient traffic using endpoint membership and retained handshake evidence |
| `process.pid` | Field 10 matched to `/proc/<PID>/fd/*`; PID from directory name | Optional first observed socket holder; retained for closure | Attribute the socket to a process |
| `process.name` | Owning PID's `comm` | Short process name; empty if unreadable | Readable process label |
| `process.executable` | Owning PID's `exe` symlink | Executable path; empty if unresolved | Identify the owning program |
| `process.entity_id` | Agent ID + owning PID + `stat` field 22 | Full SHA-256, using the same process-instance identity as process events | Correlate network and process events without relying on reusable PIDs |

Socket instances use protocol, endpoints, and inode; an unambiguous transition to inode 0 retains the tracked instance. Polling can miss connections; ownership can race with socket closure and shared descriptors can have multiple holders. Process start ticks are checked around the ownership walk. The entire `process` object is omitted when ownership is unresolved; closure context is last observed, not a fresh lookup. Failed table reads do not establish socket closure. Network tables reflect the Agent's network namespace; it does not walk `/proc/<PID>/net` or container namespaces. All other `/proc/net` entries are unused.

[`dns.go`](../internal/telemetry/network/dns.go) captures Ethernet IPv4/IPv6 UDP traffic to/from port 53 on all interfaces through `AF_PACKET` (`CAP_NET_RAW` required). It emits `dns.query` / `dns.answer`, module `telemetry.dns`, category `network`.

DNS values come from packet fields, except for host identity and process attribution. `local` is the host endpoint and `remote` its peer, for both queries and replies; when both endpoints are local, `local` identifies the DNS client. Host identity uses exact cached interface IPs and loopback, independently of internal CIDRs. When neither endpoint belongs to the host namespace, `dns.client` and `dns.server` preserve the forwarded endpoints; `local`, `remote`, and `process` are omitted. Byte offsets below start at 0 within the named header. Question/answer offsets vary with encoded names.

| Field | Source | Meaning / format | Usage |
| --- | --- | --- | --- |
| `dns.id` | DNS header bytes 0–1: ID | 16-bit transaction ID; not globally unique | Match queries and responses with endpoint context |
| `dns.type` | DNS header bytes 2–3: QR flag | `query` or `answer` | Distinguish message role |
| `dns.op_code` | DNS header bytes 2–3: opcode | Operation name, usually `QUERY` | Identify the requested operation |
| `dns.question.name` | First question: QNAME, starting at DNS byte 12 | Queried domain name | Identify the requested name |
| `dns.question.type` | First question: QTYPE | Requested record type, e.g. A/AAAA | Identify the requested data; independent of transport address family |
| `dns.question.class` | First question: QCLASS | DNS class, usually `IN` (Internet) | Interpret the question |
| `dns.question.registered_domain` | Derived from question name's last two labels | Approximate domain grouping; not public-suffix aware | Group related names |
| `dns.recursion_desired` | DNS header bytes 2–3: RD flag | Boolean: client requests recursive resolution | Describe resolver behavior requested |
| `dns.recursion_available` | DNS header bytes 2–3: RA flag | Boolean: server advertises recursion support | Describe resolver capability |
| `dns.authoritative` | DNS header bytes 2–3: AA flag | Boolean: response claims to be authoritative | Interpret response provenance |
| `dns.header_flags` | DNS header bytes 2–3: flags | Array of active qr/aa/tc/rd/ra flags; tc means truncated; null if none | Inspect message flags |
| `dns.response_code` | DNS header bytes 2–3: RCODE | Outcome such as NOERROR/NXDOMAIN; responses only | Investigate resolution success/failure |
| `dns.answers_count` | Count of parsed answer records | Number of emitted answers, capped at 64; omitted without answers | Summarize returned records |
| `dns.answers[].name` | Answer record: NAME | Domain owning the answer record | Associate returned data with a name |
| `dns.answers[].type` | Answer record: TYPE | Returned record type, e.g. A/AAAA/CNAME | Interpret record data |
| `dns.answers[].ttl` | Answer record: TTL | Cache lifetime in seconds | Understand cache duration |
| `dns.answers[].data` | Answer record: RDATA | Decoded value or possibly shortened hexadecimal fallback | Inspect returned addresses, aliases, or other data |
| `dns.resolved_ips` | Derived from A/AAAA answer RDATA | IP-address array; omitted when none | Correlate names with addresses |
| `local.ip` | IPv4 bytes 12–15 or 16–19 / IPv6 bytes 8–23 or 24–39; selected by host identity | Host endpoint IP | Identify the local client or resolver |
| `local.port` | UDP bytes 0–1 or 2–3, matching the host IP | Host UDP port as an integer | Identify the local socket |
| `remote.ip` | Other packet endpoint: IPv4 bytes 12–15 or 16–19 / IPv6 bytes 8–23 or 24–39 | Peer IP | Identify the remote resolver or client |
| `remote.port` | UDP bytes 0–1 or 2–3, matching the peer IP | Peer UDP port as an integer | Identify the remote socket |
| `dns.client.ip` | Query sender / answer recipient: IPv4 bytes 12–15 / 16–19; IPv6 bytes 8–23 / 24–39 | Client IP; only when neither endpoint is on the host | Preserve forwarded query origin |
| `dns.client.port` | Query UDP bytes 0–1 / answer bytes 2–3 | Client port as an integer; forwarded traffic only | Correlate forwarded transactions |
| `dns.server.ip` | Query recipient / answer sender: IPv4 bytes 16–19 / 12–15; IPv6 bytes 24–39 / 8–23 | Resolver IP; forwarded traffic only | Identify the forwarded resolver |
| `dns.server.port` | Query UDP bytes 2–3 / answer bytes 0–1 | Resolver port as an integer; forwarded traffic only | Identify the resolver socket |
| `network.transport` | IPv4 header byte 9 / IPv6 byte 6; must be 17 (UDP) | `udp` | Identify the captured transport |
| `network.type` | Parsed packet IP address format | `ipv4` or `ipv6` | Identify packet address family |
| `network.community_id` | Derived from transport and packet endpoints | Direction-independent Community ID v1 flow hash | Correlate query/response flows and connection observations |
| `network.direction` | Packet endpoints, configured `internal_networks`, and kernel interface addresses | Perimeter classification: internal, external, inbound, outbound, unknown | Classify each observed message relative to the perimeter |
| `process.pid` | Shared `/proc/net/udp{,6}` fields 2/3/10 matched to `/proc/<PID>/fd/*`, or matched query context | Optional local socket-owning PID | Attribute the DNS activity |
| `process.name` | Local owning PID's `comm` | Short process name; empty if unreadable | Readable local process label |
| `process.executable` | Local owning PID's `exe` symlink | Executable path; empty if unresolved | Identify the local client or resolver program |
| `process.entity_id` | Agent ID + local owning PID + `stat` field 22, or matched query context | Full SHA-256 process-instance identity | Correlate DNS and process events |

No TCP DNS, DoH/DoT, raw packet payload, authority/additional records, or full packet capture is shipped. Process attribution uses the shared UDP snapshot and PID socket links/`comm`/`exe`/`stat`; new or short-lived sockets may remain unattributed, and ambiguous socket ownership is omitted. Responses can inherit query context matched by client/resolver endpoints, transaction ID, and question for up to 5 s. The entire `process` object is omitted when attribution is unavailable.

Loopback's outgoing capture copy is skipped; its received copy is retained for both queries and responses. Genuine repeated datagrams, A/AAAA transactions, and query/response events remain distinct. Identical packets seen on different interfaces are retained when the capture metadata cannot establish that they are copies; Community ID is never a deduplication key. Observation timestamps precede process enrichment, regardless of the shipment interval.

## File changes and access

[`paths.go`](../internal/telemetry/file/paths.go) defines the fixed integrity watch list. Recursive directories: `/etc/{sudoers.d,pam.d,security,ssh,cron.d,cron.daily,cron.hourly,cron.weekly,cron.monthly,systemd/system,ld.so.conf.d,profile.d,modprobe.d,modules-load.d,apparmor.d}`, `/root/.ssh`, `/etc/apt/{sources.list.d,apt.conf.d,trusted.gpg.d}`, `/var/spool/cron/crontabs`.

Direct files: `/etc/{passwd,shadow,group,gshadow,security/opasswd,sudoers,crontab,ld.so.conf,ld.so.preload,profile,environment,default/grub,hosts,hostname,resolv.conf,nsswitch.conf,hosts.allow,hosts.deny,fstab,bash.bashrc,apt/sources.list}`, `/root/{.bashrc,.profile,.bash_login}`, `/boot/grub/grub.cfg`. Nonrecursive directories (immediate files only): `/usr/lib/systemd/system`, `/lib/systemd/system`, `/boot/grub`, `/lib/{x86_64-linux-gnu,aarch64-linux-gnu}/security`, `/usr/share/keyrings`. Missing paths are skipped; this is not a whole-filesystem baseline.

[`fim.go`](../internal/telemetry/file/fim.go) uses inotify plus hourly rescans against one serialized, persistent BoltDB baseline. Unchanged observations and repeated delete notifications emit nothing; changes and deletion/recreation remain distinct. Initial baseline emits no events; warm restarts retain existing records. New subdirectories of recursive watches are added. Renames are delete/create events; inotify overflow schedules a rescan. Individually watched files can lose their watch after replacement; rescans still compare their paths.

| Field(s) | Meaning / local use |
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

Content and stored metadata changes drive events. Creates are severity 2; attribute changes are 1. Modifications/deletions are 2, or 3 on critical paths. Entropy >7.5 raises severity to at least 3 and adds `high-entropy` / `potentially-packed` tags; it is not itself a YARA match. Deleted events can contain last-known metadata. Symlinks are recorded without hashing their target; files above the size limit have no content hash.

[`access.go`](../internal/telemetry/file/access.go) watches `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd` for open/read, and `/root/.ssh`, `/etc/ssh` for immediate-child opens. Emits `file.access`, module `telemetry.file`, category `file`, severity 3. `file.{path,name,directory}` identify the accessed file; `file.event.action=access` and `event.action=file-accessed` label the action at the document root. ATT&CK mapping is Credential Access / T1003.008 (password files) or T1552.004 (SSH paths), based on path rather than a confirmed attack. Legitimate reads, including the Agent's own, can trigger events; inotify provides no accessing PID/user. Watches are installed once, not recursively; missing/replaced paths need restart to reinstall. Repeated open/read occurrences remain distinct, with an overload cap of 200 events/s. Health is separately reported as `telemetry.file.access`; running health does not guarantee every optional watch succeeded.

## Protection and runtime logs

| Producer / event | Behavior |
| --- | --- |
| `detection.malware` / `alert` | YARA consumes `process.executable` + PID (`/proc/<PID>/exe`) or `file.path`; emits matching rules and copied process context. Category threat, kind alert, severity 3 |
| `prevention.manager` / `prevention.action` | Checks YARA method, deny-request flag, PID/start ticks and executable identity before termination |
| `prevention.execution` / `prevention.action` | Reports fanotify execution-denial decisions or response failures |
| `agent.logger` / `agent.log` | Captures the Agent's standard logger; shipper diagnostics stay local to avoid feedback loops |

Protection detail names below are literal dotted keys, except `action`, `detail`, and `method`:

| Field(s) | Meaning |
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
- Add collection-success indicators before treating empty/zero values as facts. File setuid/setgid/sticky bits are a useful gap: `file.mode` excludes those bits. More fields alone will not fix missed executions from polling.
