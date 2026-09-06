# Windows control guide

This guide covers the features added in v1.4.0 and the debugger editing tools
added in v1.5.0. The [README tool catalog](../README.md#tool-catalog) lists all
199 tools. MCP `tools/list` is the authority for input schemas, action enums
and per-operation bounds.

## Lifetimes and result semantics

Call `execution_context` before starting stateful work. It reports the actual
Windows account, token, session, desktop access, connection ID, host context
and persistence availability. These tools do not grant access to another
user's desktop, protected processes or secure desktops.

| Lifetime | Disconnect | Host exit or reboot |
|----------|------------|---------------------|
| `connection`, the default | Owned jobs/terminals are canceled, recordings and workflows stop, and debuggers detach | Live resources end |
| Explicit `persistent` on a local host | Supported resources remain available to authorized host connections | Supported checkpoint history can be recovered with interruption/gap markers; live processes and debugger sessions are not restored |

Start a host with `--local-host NAME`; connect with `--connect-host NAME`.
The bridge does not start or elevate the host. Host and client identity/token
checks still apply. `--host-state-dir` selects an absolute state directory for
an explicitly started host. This is a local named-pipe transport, not a network
service or an automatically installed Windows service.

No completed mutation is replayed after restart. Recovered watcher history is
not a live restarted watch. ETW ownership recovery reports its cleanup results
and does not reconstruct missing events.

An accepted request, written byte, signaled service or scheduled VM operation
is not application completion. Inspect the actual returned state, partial
errors, observed flags and retention gaps. Cancellation is cooperative where
Windows cannot interrupt a provider safely. Never automatically repeat a
mutation whose outcome is uncertain.

## Desktop observation and interaction

`desktop_snapshot` captures desktop, monitor, window or region pixels and can
include a bounded accessibility tree, local OCR and changed-region comparisons.
It returns physical coordinates, origin, scaling, DPI, cursor metadata and
capture limitations. A window capture is a crop of the visible desktop, not
an offscreen rendering of hidden or occluded content.

`desktop_ocr` uses installed Windows OCR support. Missing languages or provider
failures are reported rather than replaced by invented text.

`window_list` and `window_find` discover exact window references.
`window_manage` applies supported window actions to the selected window.
`ui_find` searches native UI Automation controls by window, name, automation ID,
type, process or physical bounds. Element references belong to the connection;
refresh stale references instead of guessing a new target. A truncated search
does not establish that a match is unique.

`ui_invoke` uses supported UI Automation patterns, including invoke, selection,
toggle, expand/collapse, scrolling and focus. `ui_set_value` writes native text
or numeric value patterns rather than typing into an arbitrary focused window.
`ui_text` reads bounded TextPattern text. Provider acceptance and observed
resulting state are separate.

`ui_wait` waits for a window/control condition with an explicit outcome:
`satisfied`, `timed_out`, `canceled` or `failed`. Supply an `operation_id` when
you need to cancel the wait through `desktop_cancel`.

The existing `screen_capture`, pointer and keyboard tools remain available.
Coordinates are physical desktop pixels. Input tools can affect whichever
application receives Windows input; prefer exact UI/window references when
possible. The activity overlay is notification, not consent. Passive reads do
not pulse it.

## Terminals and jobs

`terminal_create` starts an addressable ConPTY shell or REPL. `job_start`
starts a directly selected executable with captured output. Both take
`program`, `args`, optional `cwd`, per-process `env`, lifetime and bounds.
Use an explicit shell executable if shell interpretation is intended.

| Operation | Tools and behavior |
|-----------|--------------------|
| Terminal input | `terminal_input` accepts text or exact base64 bytes, with at most 65536 pending bytes. Its result describes the write, not completion of a shell command |
| Terminal output | `terminal_read` reads a bounded combined UTF-8/VT byte stream by byte cursor, with base64, a lossy preview, dropped-byte counts and gap information |
| Terminal control | `terminal_resize` changes dimensions to 1-1000 columns/rows. `terminal_interrupt` sends byte `0x03`; application console modes decide whether that interrupts anything |
| Terminal cleanup | `terminal_close` forcibly terminates the terminal's owned Job Object tree and closes ConPTY after output drains. It is not a graceful shell exit |
| Job state/output | `job_inspect`, `job_output` and `job_wait` distinguish root exit, remaining tree processes, output drain and terminal status |
| Job cancellation | `job_cancel` acts on the owned job tree, not arbitrary processes with similar names |
| Discovery/shutdown | `terminal_list` and `job_list` expose visible retained records. `host_shutdown` explicitly shuts down the resident host and its resources |

Output defaults to 256 KiB per stream and is bounded to 4 MiB per stream,
with a 64 MiB aggregate bound. Individual reads are at most 256 KiB.
A cursor read can split a UTF-8 code point; use base64 when exact bytes matter.
Do not treat ConPTY's combined stream as separate stdout and stderr.

`process_start` remains available, but the job tools provide explicit ownership,
retained output, deadlines and cancellation for work that needs those semantics.

## Watches, waits, traces and workflows

`watch_create` starts recording future filesystem, registry, service, process,
UI Automation or explicitly selected ETW events. Provider setup failures are
retained as failed watches. `events_read` returns cursor-based history with
exact filters, recording times, loss counters, retention gaps and restart gaps.
It does not reconstruct events from before recording or infer causality.

`watch_remove` stops recording while retaining history; `forget: true` also
removes a terminal watch. A delayed native shutdown can remain `stopping`.
`trace_start` and `trace_stop` specialize this interface for ETW or process
recording. Select provider GUIDs and event/process/session scope explicitly.

`wait_for` uses an absolute Unix-millisecond deadline. `background: true`
returns a wait ID. Recover retained IDs with `wait_list`, retrieve outcomes
with `wait_status`, and cancel with `wait_cancel`. Retrieving a wait does not
renew its deadline.

`workflow_start` runs a bounded, declared sequence of existing-tool actions
and event waits. Every step has a name and deadline. Action arguments or wait
filters can bind prior results with a value such as:

```json
{"$step": "launch", "pointer": "/data/field"}
```

The pointer must match the actual previous result. This is data substitution,
not code execution or autonomous planning. `continue_on_error` explicitly
allows later evidence-gathering steps after a failed step. There are no implicit
retries, rollback or replay.

Use `workflow_status`, `workflow_list` and `workflow_wait` to inspect retained
results, and `workflow_cancel` to stop future work. Canceling retrieval does not
cancel an explicitly persistent workflow. Persistent workflows own a connection
scope until completion; a child action must itself request persistent lifetime
to outlive that scope.

## Files and service configuration

Read a file with `fs_read` to obtain its exact identity and revision before a
conditional edit. UTF-8, UTF-16 LE/BE and base64 are explicit choices, and text
BOMs are validated and reported.

| File operation | Contract |
|----------------|----------|
| `fs_write` | Choose `create_new`, unconditional `atomic_replace`, revision-checked `conditional_in_place`, or explicitly supported transactional consistency. Atomic replacement requires destination-default metadata |
| `fs_patch` | Literal text replacement requires the exact revision and exact non-overlapping match count. Encoding and BOM are preserved |
| `fs_copy` | Up to 32 revision-checked files, absent destinations, explicit source-security or destination-default policy, and per-file partial results. Directories, reparse points, alternate streams and special attributes are rejected |
| `fs_move` | Exact-revision, same-volume rename to absent destinations. Preserves identity, streams and security; does not silently copy across volumes |
| Link tools | `fs_link_create`, `fs_link_inspect` and `fs_link_remove` act on link objects. Removal requires an exact revision and does not follow the target. Ordinary last-link files and volume mount points are rejected |
| Security tools | `fs_security` reports owner/group/DACL and security revision. `fs_acl_modify` and `fs_owner_set` use exact SIDs and bounded explicit scope without following reparse points |
| `fs_locks` | Reports native Restart Manager users of an exact file, including PID/creation-time identities. It is not a complete handle inventory and does not request shutdown |

Conditional in-place edits preserve metadata/security but are not crash atomic.
Native transactional file support must exist when explicitly requested; do not
assume an unsupported transaction silently falls back to another mode. DACL
merge preserves unrelated entries, while replacing a DACL with an empty list
deliberately denies access. SACL capture/editing is not included.

`service_create` and `service_configure` use exact service names and support
executable/account/dependency settings, startup configuration, description,
delayed start, recovery actions and SID settings. Passwords are write-only.
Omitted settings are retained; supported explicit empty values clear them.
Multi-stage changes report applied steps and partial failures.

`service_control` performs bounded start, graceful stop or restart using observed
service status, checkpoints and wait hints. Restart starts only after stopped
is observed. `service_delete` marks a service for deletion and can wait for
absence; deletion does not stop it or kill its process. Creating a service does
not start it.

## Network, virtualization, devices and storage

| Family | Identity and limits |
|--------|---------------------|
| Interfaces, addresses and routes | Discover GUID/LUID/index identities with `network_interfaces`. Address and route mutations require exact interface GUIDs and exact entries, preserve unrelated entries, and operate in the active store without reboot persistence |
| DNS, DHCP and adapter state | `network_dns_config` edits one family of static DNS settings; an empty server list clears its override. DHCP uses the installed NetTCPIP provider and explicit active/persistent scope. Administrative up/down is not PnP disable and does not prove connectivity |
| Proxy settings | `network_proxy_config` distinguishes machine WinHTTP settings from current-token-user WinINet LAN proxy/PAC/auto-detection. User changes require the observed SID; application caches may delay their effect |
| Wi-Fi | `network_wifi_profiles` returns exact saved profile identities and scopes without credentials. `network_wifi_connect` uses an existing profile on an exact interface. User profiles require the expected SID; association is not proof of Internet access |
| WSL | `wsl_instances` reads current-user registration identities without starting a distribution. `wsl_manage` starts owned status/start/stop/export/import jobs with exact registration GUID, expected name and user SID where required. Start uses a bounded keepalive |
| Hyper-V | `hyperv_instances` reads installed-provider state. `hyperv_manage` runs owned start, graceful-stop, explicit-power-off, save, export or in-place `.vmcx` registration jobs against exact VM identities |
| PnP devices | `device_list` returns a bounded exact-instance inventory. `device_set_state` enables, disables or restarts that instance and reports observed state plus reboot/restart flags. Acceptance alone does not prove a complete restart cycle |
| Drivers | `driver_list` reports device bindings, not every unbound staged package. `driver_package` distinguishes staging from installing by normal driver rank; removal targets an exact unused `oemN.inf`, checks present/non-present bindings and never forces removal |
| Volumes | `volume_list` returns volume GUID identities. `volume_set` changes labels or exact mount points, verifying removal targets and refusing unrelated mapping replacement. It does not format or forcibly dismount volumes |
| Disk images | `virtual_disk` inspects/attaches/detaches local VHD/VHDX/ISO files. Mutations require `expected_identity` from a prior inspection. Attach defaults to read-only/no-drive-letter and survives handle closure until explicit detach, not reboot |

Address duplicate-address-detection state, DNS configuration, DHCP activation
and link state are observations, not proof of usable networking. Address/route
changes do not implicitly disable DHCP or rewrite other entries.

WSL and Hyper-V tools do not install or enable Windows features. Provider-job
creation is not completion: use `job_inspect`, `job_output` and `job_wait`.
An accepted VMMS operation can outlive cancellation of the launching job.
User-scoped operations use the actual token user, not an inferred desktop user.

Virtual-disk attachment is distinct from host-resource lifetime. UNC/reparse
paths and session-lifetime attachments are unsupported. Device and driver tools
report reboot requirements without restarting Windows.

## Audio and native provider updates

`audio_meter` reads endpoint/channel peaks without recording. `audio_sessions`
lists exact session instance IDs and process identities.
`audio_session_volume` changes playback-session volume/mute by exact session ID
or unambiguous PID; PID-only mutation requires the observed process creation
time. Capture-session reads have endpoint-wide scope, so capture volume changes
use `audio_volume` explicitly.

`audio_record` records microphone input or playback loopback only when explicitly
requested with mode, duration and a new absolute WAV path. It uses the endpoint's
actual mix format, bounds memory/file size, refuses overwrites and removes
incomplete artifacts on cancellation.

The existing firewall, event-log, Task Scheduler, user/group, display and audio
tools include native implementations. Retained compatibility/provider paths
remain part of their schemas. Existing command, software, environment, Windows
feature and update tools are still available.

## Process diagnostics

Start with `diagnostics_process`. Its PID plus exact FILETIME `creation_time`
identifies the target and rejects PID reuse. It also reports architecture,
session, token privilege and protection information.

`process_dump` writes a mini or full dump to a new exclusive local path with
explicit byte/time bounds. Existing files, device paths, alternate streams and
network shares are rejected. Incomplete artifacts are cleaned up.

`process_stacks` captures bounded native user-mode stacks, including supported
x64-to-WOW64 contexts. Each suspension owned by the capture is balanced.
Partial/unavailable unwinds are reported. `process_wait_chain` uses native WCT
to inspect waits and cycles without claiming to prove a failure's cause.
`process_handles` uses PSS handle metadata rather than potentially blocking
object-name queries.

## Debugger sessions and editing

`debug_attach` takes exact PID/creation time. `debug_launch` directly starts an
executable without a shell and debugs only that process, not its children.
Launched stdin/stdout/stderr go to NUL; debug events capture
`OutputDebugString`, not console output.

Use `debug_list` and `debug_inspect` to find the session and its current stop.
`debug_events` reads bounded history by cursor and reports retention gaps.
`debug_break` requests a stop; wait until inspection actually reports stopped.
`debug_continue` requires the exact current `stop_id`.

`debug_command` remains read-only: `threads`, `modules`, `registers` and
`read_memory`. `debug_evaluate` accepts an unsigned literal or `@register`,
optionally followed by checked `+` or `-` of a constant. It does not run scripts,
call target functions or interpret arbitrary DbgEng commands.

### Guarded memory writes

`debug_memory_write` requires session `id`, current `stop_id`, numeric `address`,
replacement `bytes_base64`, and same-length `expected_base64` containing the
currently observed bytes. Read the target first. The following is a
`tools/call` parameter example; replace the session, stop, address and byte
values with observations from your own disposable target:

```json
{
  "name": "debug_memory_write",
  "arguments": {
    "id": "session-id-from-debug_attach",
    "stop_id": "42",
    "address": "140700000000000",
    "expected_base64": "AQIDBA==",
    "bytes_base64": "BQYHCA=="
  }
}
```

The result includes the before/requested/readback bytes, requested/written/
readback counts, native API status, `complete`, `partial`, errors, protection
restoration and instruction-cache flush status. Executable writes flush the
instruction cache. Temporary page protection changes are restored on cleanup.
Failed or short writes are not retried automatically.

Writes are limited to 1-65536 bytes in one committed region with uniform
protection. Guard/no-access pages and overlap with reserved breakpoint
addresses or pending instructions are rejected. Stale stops and mismatched
expected bytes do not write.

### Software breakpoints and stepping

`debug_breakpoint` uses a typed `action`: `add`, `list`, `enable`, `disable`
or `remove`. Every action requires session `id` and current `stop_id`.
Addressed actions require an exact numeric `address`; `add` also requires
`expected_byte` in 0-255. An existing INT3 (`204`) is rejected because its
ownership is ambiguous.

```json
{
  "name": "debug_breakpoint",
  "arguments": {
    "id": "session-id-from-debug_attach",
    "stop_id": "42",
    "action": "add",
    "address": "140700000000000",
    "expected_byte": "144"
  }
}
```

This independent example expects an observed NOP byte (`144`), not the memory
contents in the preceding write example. Addresses are examples, not usable
targets.

Owned hits restore the original byte and rewind the instruction pointer.
Continuing an owned hit single-steps its original instruction, suspends other
target threads with separately owned counts, and reinserts an enabled
breakpoint. Already queued traps from other threads are handled without
skipping the original instruction.

`debug_step` takes session `id` and current `stop_id`, steps the stopped event
thread, and requests a new stop. Inspect the `step_completed` event and the
resulting stop's `reason: "single_step"`;
acceptance is not step completion. Pre-existing trap flags are rejected rather
than claimed. Breakpoint stops identify their exact owned address. Initial
Windows breaks and foreign exceptions are distinguished; default continuation
passes foreign exceptions back to the target.

| Limit | Behavior |
|-------|----------|
| Architectures | x86, x64 and supported x64-to-WOW64 instruction contexts; no hardware breakpoints or instruction emulation |
| WOW64 loader stops | Native 64-bit loader stops cannot be stepped through the x86 context; continue to an x86 stop first |
| Breakpoint addresses | At most 128 distinct addresses per session. Removed addresses retain metadata and remain excluded from memory writes until detach so queued traps can be recognized |
| Pending step | A step still pending after five seconds initiates detach cleanup. Native cleanup may take longer |
| Debug sessions | At most eight active sessions and 32 retained records per manager |
| Ownership evidence | Allocation/region metadata plus expected bytes; an external remap recreated with identical metadata and bytes cannot be distinguished |

`debug_detach`, disconnect and host shutdown restore owned patches before
releasing the target, balance owned suspension counts and clear owned stepping
state. Changed or unmapped regions are not overwritten to force cleanup to
appear successful; cleanup failures are reported.

Detach does not kill either attached or launched targets. `debug_terminate`
is explicit and limited to a process launched by that debugger session.
Debugger state never survives host exit or reboot.
