# SentinelEDR — Requirements Document v1.0

**A Proof-of-Concept Endpoint Detection & Response Agent for Windows x64**

Version 1.0 — Claude Code Implementation Phases
March 2026

> Architecture derived from sensor models in *Evading EDR* by Matt Hand (No Starch Press, 2023)
> Phases structured for iterative implementation with Claude Code

---

## How To Use This Document With Claude Code

This requirements document is structured as a sequence of implementation phases, each broken into discrete tasks sized for a single Claude Code session. Each task includes the specific files to create or modify, concrete acceptance criteria, and an estimated complexity rating.

### Workflow Per Task

1. Open a Claude Code session and provide the task ID (e.g., "Implement task P1-T3") along with this document as context.
2. Claude Code generates the implementation. Review the output against the acceptance criteria listed in the task row.
3. Run the specified build/test commands. If the acceptance criteria pass, commit and move to the next task.
4. If a task fails or needs iteration, stay in the same session and refine before moving on. Tasks within a phase are ordered by dependency.

### Complexity Ratings

- **S (Small):** Single-file scaffolding, headers, configs. Typically <200 lines. One session.
- **M (Medium):** Single component with moderate logic. 200–600 lines. One session, possibly two.
- **L (Large):** Multi-file component with kernel/user interaction, IPC, or complex logic. 500–1500 lines. May need 2–3 sessions.
- **XL (Extra Large):** Full subsystem with cross-component integration. Break into sub-tasks within the session. 2–4 sessions.

### Session Context Tips

- At the start of each session, paste the relevant phase section from this doc (or the full doc if within context limits).
- Reference the repo structure and `common/` headers so Claude Code knows where types and IPC definitions live.
- For kernel-mode tasks, remind Claude Code of WDK constraints: C17, no C++ exceptions, no STL, IRQL discipline.
- For tasks that depend on prior tasks, ensure the prior output is committed and referenceable in the working tree.

---

## Repository Structure

All phases build into this monorepo layout. Phase 0 scaffolds it; subsequent phases populate the directories.

| Path | Purpose |
|------|---------|
| `CMakeLists.txt` | Top-level CMake. Detects WDK, builds all sub-projects. |
| `common/` | Shared headers: telemetry event structs, IPC protocol, error codes, constants. |
| `common/telemetry.h` | Event envelope struct + per-sensor payload unions. Used by every component. |
| `common/ipc.h` | Named pipe protocol constants, message framing, serialization helpers. |
| `common/constants.h` | Pipe names, driver device names, IOCTL codes, version string. |
| `sentinel-drv/` | Kernel-mode driver (WDM). Callbacks, minifilter, WFP callout. |
| `sentinel-drv/CMakeLists.txt` | WDK build config for `.sys` output. |
| `sentinel-hook/` | User-mode hooking DLL. Inline trampoline hooks on ntdll. |
| `sentinel-agent/` | User-mode service. ETW consumer, AMSI provider, scanner, rule engine. |
| `sentinel-cli/` | Console management tool. |
| `rules/` | YAML detection rule definitions. |
| `yara-rules/` | YARA rule files for file and memory scanning. |
| `tests/` | Integration test harness + Ch. 13 attack chain automation. |
| `scripts/` | Build helpers, driver install/uninstall, test-signing setup. |
| `docs/` | Architecture diagrams, API docs, this requirements doc. |

---

## Phase 0: Project Scaffolding

**Goal:** Establish the monorepo, build system, shared headers, and IPC protocol so all subsequent phases have a stable foundation to build on.

**Book reference:** Chapter 1 (EDR-chitecture) — component overview, telemetry model, agent design tiers.

### P0-T1 — Initialize Monorepo `[S]`

**Task:** Initialize monorepo with directory structure, top-level `CMakeLists.txt`, `.gitignore`, `README.md`, `LICENSE`. CMake must detect WDK and configure kernel vs. user-mode sub-projects.

**Files:** `CMakeLists.txt`, `.gitignore`, `README.md`, all subdirectory `CMakeLists.txt` stubs

**Acceptance Criteria:** `cmake -B build` succeeds with WDK detected. Each sub-project stub compiles (empty `main`/`DriverEntry`).

### P0-T2 — Shared Telemetry Schema `[M]`

**Task:** Define the shared telemetry event envelope and per-sensor payload structures in `common/telemetry.h`. This is the canonical event schema used by every component. Include: `event_id` (GUID), `timestamp` (LARGE_INTEGER), source enum, process context struct, and a tagged union for sensor-specific payloads.

**Files:** `common/telemetry.h`

**Acceptance Criteria:** Header compiles in both kernel-mode (C17, WDK) and user-mode (C++20) contexts without errors. All event types from Chapters 2–12 have a payload variant.

### P0-T3 — IPC Protocol `[M]`

**Task:** Define IPC protocol in `common/ipc.h`. Named pipe `\\.\pipe\SentinelTelemetry` for user-mode components. Filter communication port (`FltCreateCommunicationPort`) protocol for driver→agent. Message framing: 4-byte length prefix + serialized event. Include connect/disconnect handshake.

**Files:** `common/ipc.h`, `common/ipc_serialize.h`

**Acceptance Criteria:** Header compiles in both modes. Serialization round-trips a test event correctly (unit test in `tests/`).

### P0-T4 — Constants `[S]`

**Task:** Define constants in `common/constants.h`: device name (`\Device\SentinelDrv`), symbolic link, pipe names, IOCTL codes for CLI→agent commands (status, scan, rule reload), driver version, minifilter altitude (320000 range), WFP sublayer/callout GUIDs.

**Files:** `common/constants.h`

**Acceptance Criteria:** No magic numbers in any subsequent phase code — everything references `constants.h`.

### P0-T5 — Install Scripts `[S]`

**Task:** Create driver install/uninstall scripts. PowerShell scripts for: enabling test-signing (`bcdedit`), creating the driver service (`sc create`), starting/stopping, and kdnet setup instructions.

**Files:** `scripts/install-driver.ps1`, `scripts/uninstall-driver.ps1`, `scripts/setup-testsigning.ps1`

**Acceptance Criteria:** Scripts run without error on a clean Win10/11 x64 VM. Driver service appears in `sc query` output.

---

## Phase 1: Kernel Driver — Process & Thread Callbacks

**Goal:** Build the kernel driver skeleton and implement the first two callback types: process creation/termination and thread creation/termination. This is the foundation of all kernel-level telemetry.

**Book reference:** Chapter 3 (Process- and Thread-Creation Notifications).

### P1-T1 — Driver Skeleton & Communication Port `[M]`

**Task:** Implement `DriverEntry` and `DriverUnload`. Create device object, symbolic link. Register and clean up filter communication port (`FltCreateCommunicationPort`) for sending telemetry to the agent. Implement port connect/disconnect callbacks.

**Files:** `sentinel-drv/main.c`, `sentinel-drv/comms.c`, `sentinel-drv/comms.h`

**Acceptance Criteria:** Driver loads and unloads cleanly (no BSOD, no leaks under Driver Verifier). Communication port is created and visible to user-mode.

### P1-T2 — Process Creation Callback `[L]`

**Task:** Register process-creation callback via `PsSetCreateProcessNotifyRoutineEx`. In the callback, populate a `SENTINEL_EVENT` with: image path, command line (from PEB), PID, PPID, creating thread ID, token info (user SID, integrity level via `SeQueryInformationToken`), and PE metadata. Send event over filter communication port.

**Files:** `sentinel-drv/callbacks_process.c`, `sentinel-drv/callbacks_process.h`

**Acceptance Criteria:** When `notepad.exe` is launched, a correctly populated process-create event is received by a test consumer on the filter port. All fields are non-null. Event arrives within <50ms of process start.

### P1-T3 — Thread Creation Callback `[M]`

**Task:** Register thread-creation callback via `PsSetCreateThreadNotifyRoutineEx`. Populate event with: TID, start address, owning PID, creating PID/TID. Flag remote thread creation (creating PID != owning PID).

**Files:** `sentinel-drv/callbacks_thread.c`, `sentinel-drv/callbacks_thread.h`

**Acceptance Criteria:** Launching a process generates both process-create and thread-create events. A remote thread injection (test with `CreateRemoteThread`) is flagged with `remote=true`.

### P1-T4 — Test Consumer `[M]`

**Task:** Build a minimal user-mode test consumer that connects to the filter communication port, receives events, deserializes them, and prints JSON to stdout. This is a throwaway diagnostic tool but validates the entire driver→user-mode pipeline.

**Files:** `tests/test_consumer.c`

**Acceptance Criteria:** Run `test_consumer.exe`, launch processes, see JSON events stream to console. Ctrl+C disconnects cleanly.

---

## Phase 2: Kernel Driver — Object, Image-Load, and Registry Callbacks

**Goal:** Complete the kernel callback suite: object handle notifications, image-load notifications (including the KAPC injection infrastructure), and registry notifications.

**Book reference:** Chapters 4 (Object Notifications), 5 (Image-Load and Registry Notifications).

### P2-T1 — Object Handle Callbacks `[L]`

**Task:** Register object callbacks via `ObRegisterCallbacks`. Monitor `OB_OPERATION_HANDLE_CREATE` and `OB_OPERATION_HANDLE_DUPLICATE` for Process and Thread types. Emit event with: source PID/TID, target PID, requested access mask, granted access mask, operation type. Configure a list of protected process names (`lsass.exe`, `csrss.exe`) to watch.

**Files:** `sentinel-drv/callbacks_object.c`, `sentinel-drv/callbacks_object.h`

**Acceptance Criteria:** Opening a handle to `lsass.exe` with `PROCESS_VM_READ` generates an object-notification event. Normal handle operations to non-protected processes are filtered out (no event flood).

### P2-T2 — Image-Load Callback `[L]`

**Task:** Register image-load callback via `PsSetLoadImageNotifyRoutineEx`. Emit event with: full image path, base address, image size, PID, and signing status (via CI functions or `SeValidateImageHeader`). Populate a per-process loaded-module list in a driver-managed hash table.

**Files:** `sentinel-drv/callbacks_imageload.c`, `sentinel-drv/callbacks_imageload.h`, `sentinel-drv/process_table.c`

**Acceptance Criteria:** Loading a DLL (e.g., `rundll32` with a test DLL) generates an image-load event with correct path and signature status. Unsigned DLLs are flagged.

### P2-T3 — KAPC Injection `[XL]`

**Task:** Implement KAPC injection infrastructure triggered by image-load callback. When a new process loads `ntdll.dll`, resolve `LdrLoadDll` address from the mapped ntdll, allocate user-mode memory for the APC routine, initialize KAPC structure, and queue it to load `sentinel-hook.dll`. Include a configurable exclusion list (don't inject into system-critical processes).

**Files:** `sentinel-drv/kapc_inject.c`, `sentinel-drv/kapc_inject.h`

**Acceptance Criteria:** A newly spawned user-mode process (e.g., `notepad.exe`) has `sentinel-hook.dll` loaded in its module list (visible in Process Explorer or `!peb` in WinDbg). Injection does not occur for excluded processes.

### P2-T4 — Registry Callback `[L]`

**Task:** Register registry callback via `CmRegisterCallbackEx`. Monitor key create/open, value set/delete, key rename. Emit event with: operation type, full key path, value name, data type, data content (truncated at 4KB). Implement altitude-based filtering to reduce noise (ignore `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer` frequent writes).

**Files:** `sentinel-drv/callbacks_registry.c`, `sentinel-drv/callbacks_registry.h`

**Acceptance Criteria:** Creating a Run key persistence entry generates a registry event. High-frequency Explorer registry chatter is filtered out. No measurable performance degradation during normal use.

---

## Phase 3: Function-Hooking DLL

**Goal:** Build the user-mode DLL that gets injected via KAPC (Phase 2) and hooks ntdll functions to capture userland API call telemetry.

**Book reference:** Chapter 2 (Function-Hooking DLLs).

### P3-T1 — DLL Skeleton & Hook Engine `[L]`

**Task:** Create the DLL skeleton with `DllMain` handling `DLL_PROCESS_ATTACH` (install hooks) and `DLL_PROCESS_DETACH` (remove hooks). Implement a hook installation framework: given a function name and module, patch the first bytes with a JMP to our detour, save original bytes in a trampoline. Use a custom mini-Detours implementation (not the full MS Detours library) for educational value.

**Files:** `sentinel-hook/main.c`, `sentinel-hook/hook_engine.c`, `sentinel-hook/hook_engine.h`

**Acceptance Criteria:** DLL loads into a test process (manual `LoadLibrary`). `hook_engine` correctly patches and restores a test function (e.g., `kernel32!Sleep`). Trampoline calls the original function successfully.

### P3-T2 — Core Injection-Detection Hooks `[L]`

**Task:** Implement detour functions for the core injection-detection hooks: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtMapViewOfSection`, `NtQueueApcThread`. Each detour logs: function name, all parameters, calling module (via return address → module lookup), and return value. Events are sent to the agent over the named pipe.

**Files:** `sentinel-hook/hooks_memory.c`, `sentinel-hook/hooks_thread.c`, `sentinel-hook/hooks_section.c`

**Acceptance Criteria:** A test program that calls `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` generates three hook events with correct parameter values on the named pipe.

### P3-T3 — Remaining Hooks & Stack Hash `[M]`

**Task:** Implement remaining hooks: `NtReadVirtualMemory`, `NtOpenProcess`, `NtSuspendThread`, `NtResumeThread`, `NtUnmapViewOfSection`, `NtCreateSection`. Add stack hash computation (hash of return addresses on the call stack) to each event for behavioral correlation.

**Files:** `sentinel-hook/hooks_process.c`, `sentinel-hook/hooks_section.c` (extend)

**Acceptance Criteria:** All 12 hooked functions emit events. Stack hash is consistent for the same call path and different for different paths.

### P3-T4 — Named Pipe Client `[M]`

**Task:** Implement the named pipe client in the DLL. Connect to `\\.\pipe\SentinelTelemetry` on `DLL_PROCESS_ATTACH`. Buffer events if pipe is unavailable (ring buffer, 1000 events max). Reconnect on pipe drop. Serialize events using the `common/ipc` format.

**Files:** `sentinel-hook/pipe_client.c`, `sentinel-hook/pipe_client.h`

**Acceptance Criteria:** DLL sends events even if the agent starts after the hooked process. Buffer drains when pipe becomes available. No crash or hang if pipe is permanently unavailable.

---

## Phase 4: Agent Service — Core

**Goal:** Build the agent service that aggregates telemetry from the driver and hooking DLL, and implements the basic detection rule engine.

**Book reference:** Chapter 1 (detection logic, brittle vs. robust detections, Elastic rule model).

### P4-T1 — Service Skeleton & Pipeline `[L]`

**Task:** Create the agent as a Windows service (`SERVICE_WIN32_OWN_PROCESS`). Implement service control handler (start, stop, pause). On start: connect to driver filter communication port, create named pipe server for hook DLL connections, initialize event processing pipeline (multi-threaded: receiver threads → shared queue → processing thread).

**Files:** `sentinel-agent/main.cpp`, `sentinel-agent/service.cpp`, `sentinel-agent/pipeline.cpp`, `sentinel-agent/pipeline.h`

**Acceptance Criteria:** Service installs and starts via `sc create` / `sc start`. Connects to driver port. Named pipe server accepts connections. Events from both sources appear in the processing queue.

### P4-T2 — Event Processing & JSON Logging `[M]`

**Task:** Implement the event processing pipeline. Deserialize events from both sources into the common `SENTINEL_EVENT` struct. Enrich events with process context (maintain a process table with PID → image path, command line, user, parent, integrity level). Write all events to a JSON-lines log file (configurable path).

**Files:** `sentinel-agent/event_processor.cpp`, `sentinel-agent/process_table.cpp`, `sentinel-agent/json_writer.cpp`

**Acceptance Criteria:** Launch processes, inject DLLs, open handles — all events appear in the JSON log with correct process context enrichment. Log file rotates at 100MB.

### P4-T3 — Single-Event Rule Engine `[L]`

**Task:** Implement the single-event rule engine. Parse YAML rule files at startup. Each rule specifies: source filter, field conditions (equals, contains, regex, greater-than), severity, action (LOG/BLOCK). Evaluate each incoming event against all matching rules. Emit alert events (separate log + future dashboard hook).

**Files:** `sentinel-agent/rules/rule_engine.cpp`, `sentinel-agent/rules/rule_parser.cpp`, `sentinel-agent/rules/rule_types.h`

**Acceptance Criteria:** A YAML rule matching "process_create where image_path contains cmd.exe and parent_image contains excel.exe" fires an alert when that parent-child relationship occurs. Non-matching events pass through without alert.

### P4-T4 — Sequence Rule Engine `[XL]`

**Task:** Implement sequence rule evaluation. Maintain a sliding time-window state machine per process. Rules define ordered event sequences with a time constraint (e.g., `alloc(RW)` → `protect(RX)` → `create_thread` within 5s from same PID). On complete match, fire alert.

**Files:** `sentinel-agent/rules/sequence_engine.cpp`

**Acceptance Criteria:** The Ch. 13 shellcode runner pattern (`VirtualAlloc` → `VirtualProtect(RX)` → `CreateThread`) fires a sequence alert. Partial matches that exceed the time window are discarded.

### P4-T5 — Threshold Rule Engine `[M]`

**Task:** Implement threshold rules. Count events matching a filter within a sliding window. Fire alert when threshold exceeded. Example: >3 handle requests to `lsass.exe` with `PROCESS_VM_READ` within 30s.

**Files:** `sentinel-agent/rules/threshold_engine.cpp`

**Acceptance Criteria:** Rapidly opening handles to `lsass.exe` fires a threshold alert. Slow operations below threshold do not fire.

---

## Phase 5: Filesystem Minifilter

**Goal:** Add the minifilter component to the kernel driver for filesystem I/O monitoring, file scanning triggers, and named pipe detection.

**Book reference:** Chapter 6 (Filesystem Minifilter Drivers).

### P5-T1 — Minifilter Registration & I/O Callbacks `[L]`

**Task:** Register the minifilter with `FltRegisterFilter`. Define altitude in the FSFilter Anti-Virus range (320000–329998). Register pre- and post-operation callbacks for: `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (rename/delete). Implement `FLT_PREOP_SUCCESS_WITH_CALLBACK` / `FLT_PREOP_SUCCESS_NO_CALLBACK` filtering to skip excluded paths (`Windows\`, `Program Files\`, etc.).

**Files:** `sentinel-drv/minifilter.c`, `sentinel-drv/minifilter.h`

**Acceptance Criteria:** `fltmc` shows the minifilter loaded at the correct altitude. Creating/writing/deleting files in non-excluded paths generates events. System directories are excluded (no event flood).

### P5-T2 — File Hashing `[L]`

**Task:** In the post-create callback, compute SHA-256 hash of new/modified files asynchronously (work item queue to avoid blocking the I/O path). Emit file event with: path, operation, requesting PID, hash, file size. Cap hash computation at 50MB files.

**Files:** `sentinel-drv/file_hash.c`, `sentinel-drv/file_hash.h`

**Acceptance Criteria:** Dropping a test `.exe` to disk generates a file event with correct SHA-256 hash. Files >50MB emit events with `hash="skipped"`. No noticeable I/O latency on normal file operations.

### P5-T3 — Named Pipe Monitoring `[M]`

**Task:** Add named pipe monitoring via `IRP_MJ_CREATE_NAMED_PIPE`. Emit event with pipe name, creating PID, access mode. Build a list of suspicious default pipe names (Cobalt Strike defaults: `\MSSE-*`, `\msagent_*`, `\postex_*`, etc.).

**Files:** `sentinel-drv/minifilter_pipes.c`

**Acceptance Criteria:** Creating a named pipe with a Cobalt Strike default name generates an alert-priority event. Normal named pipe creation (e.g., from Chrome) generates a low-priority event.

### P5-T4 — YARA Rules `[S]`

**Task:** Write 3–5 YARA rules for common malware indicators: XLL files with shellcode patterns, UPX-packed PEs, Cobalt Strike beacon config patterns, Mimikatz string patterns. Place in `yara-rules/` directory.

**Files:** `yara-rules/*.yar`

**Acceptance Criteria:** YARA rules compile without errors. Manual `yara` scan against known-bad samples matches correctly.

---

## Phase 6: Network Filter (WFP Callout)

**Goal:** Add the WFP callout driver for network traffic monitoring, enabling C2 beaconing detection and lateral movement visibility.

**Book reference:** Chapter 7 (Network Filter Drivers).

### P6-T1 — WFP Callout Registration `[L]`

**Task:** Implement WFP callout registration: open filter engine session (`FwpmEngineOpen`), register callouts (`FwpsCalloutRegister`), add callouts to engine (`FwpmCalloutAdd`), create sublayer, add filter objects. Target layers: `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (outbound), `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` (inbound).

**Files:** `sentinel-drv/wfp_callout.c`, `sentinel-drv/wfp_callout.h`

**Acceptance Criteria:** WFP callout is registered (visible via `netsh wfp show state`). No network disruption on the test VM.

### P6-T2 — Network Event Classification `[M]`

**Task:** In the classify callback, extract: local/remote IP, local/remote port, protocol, PID (from `FWPS_METADATA_FIELD_PROCESS_ID`), direction. Emit network event over filter communication port. Implement rate limiting (max 100 events/sec per PID) to prevent flood from chatty processes.

**Files:** `sentinel-drv/wfp_classify.c`

**Acceptance Criteria:** Opening a browser generates network events with correct IP/port/PID. Rate limiting caps events from a single process. DNS and HTTPS connections are captured.

### P6-T3 — Connection Table `[M]`

**Task:** Maintain a connection table in the agent (not the driver) that tracks: PID, remote IP, remote port, connection count, first-seen, last-seen, total bytes. Expose via CLI query. This enables beaconing detection in Phase 8.

**Files:** `sentinel-agent/network_table.cpp`, `sentinel-agent/network_table.h`

**Acceptance Criteria:** After browsing several sites, `sentinel-cli connections` shows a table of active connections with correct metadata.

---

## Phase 7: ETW Consumer & AMSI Provider

**Goal:** Add the user-mode ETW consumer and AMSI provider to the agent, covering script-level and .NET telemetry.

**Book reference:** Chapter 8 (Event Tracing for Windows), Chapter 10 (Antimalware Scan Interface).

### P7-T1 — ETW Consumer Framework + .NET Provider `[L]`

**Task:** Implement the ETW consumer framework in the agent: create a real-time trace session (`StartTrace`), enable providers (`EnableTraceEx2`), process events in a callback (`OpenTrace`/`ProcessTrace`). Start with one provider: `Microsoft-Windows-DotNETRuntime` (for .NET assembly detection, as in the Ch. 8 case study).

**Files:** `sentinel-agent/etw/etw_consumer.cpp`, `sentinel-agent/etw/etw_consumer.h`, `sentinel-agent/etw/provider_dotnet.cpp`

**Acceptance Criteria:** Running a .NET assembly (e.g., Seatbelt) generates ETW events captured by the consumer with assembly name and class names visible in the event payload.

### P7-T2 — Additional ETW Providers `[L]`

**Task:** Add providers: `Microsoft-Windows-PowerShell` (script block logging), `Microsoft-Windows-DNS-Client` (DNS resolution), `Microsoft-Windows-Security-Kerberos` (auth events), `Microsoft-Windows-Services` (service install). Each provider gets its own parser module.

**Files:** `sentinel-agent/etw/provider_powershell.cpp`, `provider_dns.cpp`, `provider_kerberos.cpp`, `provider_services.cpp`

**Acceptance Criteria:** Running encoded PowerShell, performing `nslookup`, requesting a Kerberos ticket, and installing a service each generate parsed events in the telemetry log.

### P7-T3 — AMSI & RPC ETW Providers `[M]`

**Task:** Add providers: `Microsoft-Antimalware-Scan-Interface` (AMSI events from OS-level), `Microsoft-Windows-RPC` (RPC operations). Add `Microsoft-Windows-Kernel-Process` as a redundant telemetry source that cross-validates against driver process callbacks.

**Files:** `sentinel-agent/etw/provider_amsi.cpp`, `provider_rpc.cpp`, `provider_kernelprocess.cpp`

**Acceptance Criteria:** AMSI scan events appear for PowerShell execution. RPC events appear during remote operations. Kernel-Process events correlate with driver events (same PID/timestamp).

### P7-T4 — Custom AMSI Provider `[XL]`

**Task:** Implement custom AMSI provider (COM DLL registered via `IAntimalwareProvider`). On `AmsiScanBuffer`, evaluate content against YARA rules and a string-signature list. Return `AMSI_RESULT_DETECTED` for matches. Register provider on agent startup, unregister on shutdown.

**Files:** `sentinel-agent/amsi/amsi_provider.cpp`, `sentinel-agent/amsi/amsi_provider.h`, `sentinel-agent/amsi/amsi_register.cpp`

**Acceptance Criteria:** Running `Invoke-Mimikatz` (or a test string signature) in PowerShell triggers an AMSI detection from the SentinelEDR provider. Benign scripts pass through clean.

---

## Phase 8: Scanner Engine & Memory Scanning

**Goal:** Implement on-access file scanning, on-demand scanning, and memory scanning for unbacked executable regions.

**Book reference:** Chapter 9 (Scanners).

### P8-T1 — YARA Scanner Integration `[M]`

**Task:** Integrate libyara as a static library in the agent build. Implement a scanner module that loads rules from `yara-rules/` at startup and supports hot-reload (SIGHUP or CLI command). Expose `scan_file(path)` and `scan_buffer(ptr, size)` APIs.

**Files:** `sentinel-agent/scanner/yara_scanner.cpp`, `sentinel-agent/scanner/yara_scanner.h`, `CMakeLists.txt` (libyara)

**Acceptance Criteria:** YARA rules from Phase 5 match against test malware samples via `scan_file()`. `scan_buffer()` matches an in-memory test pattern. Hot-reload picks up new rules without restart.

### P8-T2 — On-Access Scanning `[M]`

**Task:** Implement on-access scanning: when the minifilter emits a file-create/write event with a hash, the agent calls `scan_file()` on the path. If YARA matches, emit a scanner alert with rule name, file path, and match details. Implement a scan cache (hash → last result) to avoid re-scanning unchanged files.

**Files:** `sentinel-agent/scanner/onaccess_scanner.cpp`

**Acceptance Criteria:** Dropping a YARA-matching test file to disk triggers an on-access scan alert within 2 seconds. Dropping the same file again hits the cache (no re-scan). A benign file generates no alert.

### P8-T3 — Memory Scanner `[L]`

**Task:** Implement memory scanner. On trigger (from sequence rule or manual CLI), enumerate target process memory regions via `NtQueryVirtualMemory`. Identify executable regions not backed by an image file (`MEM_PRIVATE` + `PAGE_EXECUTE_*`). Read region contents via `NtReadVirtualMemory`. Scan against YARA rules.

**Files:** `sentinel-agent/scanner/memory_scanner.cpp`

**Acceptance Criteria:** A test process that allocates RWX memory, writes a YARA-matching pattern, and changes to RX is detected by the memory scanner. Legitimate process memory (backed by images) is not flagged.

---

## Phase 9: CLI & Operational Interface

**Goal:** Build the management CLI and finalize the operational interface for interacting with the running agent.

**Book reference:** Chapter 1 (agent design, SOC workflow).

### P9-T1 — Core CLI Commands `[M]`

**Task:** Implement `sentinel-cli` with subcommands: `status` (agent health, driver loaded, sensor states), `alerts` (tail recent alerts with severity filter), `scan <path>` (trigger on-demand scan), `rules reload` (hot-reload rules). Communicate with agent over a separate named pipe for commands.

**Files:** `sentinel-cli/main.cpp`, `sentinel-cli/commands/*.cpp`, `sentinel-agent/cmd_handler.cpp`

**Acceptance Criteria:** Each subcommand returns expected output. `status` shows all sensors green. `alerts` streams real-time alerts. `scan` on a test file returns result within 5s. `rules reload` picks up new YAML.

### P9-T2 — Inspection Commands `[M]`

**Task:** Add CLI subcommands: `connections` (show network connection table from Phase 6), `processes` (list tracked processes with integrity level and loaded modules), `hooks` (show hook status per process). Format output as tables or JSON (`--json` flag).

**Files:** `sentinel-cli/commands/connections.cpp`, `processes.cpp`, `hooks.cpp`

**Acceptance Criteria:** `connections` shows the same data as the internal network table. `processes` lists all tracked PIDs with correct metadata. `hooks` confirms `sentinel-hook.dll` is loaded in target processes.

### P9-T3 — Configuration File `[M]`

**Task:** Implement agent configuration file (TOML or INI). Configurable: log path, log rotation size, sensor enable/disable flags, exclusion lists (process names for hook injection, file paths for minifilter), ETW provider enable/disable, scan cache TTL, named pipe buffer size.

**Files:** `sentinel-agent/config.cpp`, `sentinel-agent/config.h`, `sentinel-agent/sentinel.conf`

**Acceptance Criteria:** Disabling a sensor in config and restarting the agent actually stops that sensor's telemetry. Exclusion lists are honored.

---

## Phase 10: Integration Testing — Chapter 13 Attack Chain

**Goal:** Validate the complete system against the book's case study. Every phase of the attack should produce observable, alerted telemetry.

**Book reference:** Chapter 13 (Case Study: A Detection-Aware Attack).

### P10-T1 — Test XLL Payload `[M]`

**Task:** Write the test XLL payload from Chapter 13 Listing 13-1: `DllMain` + `xlAutoOpen` with XOR-encoded shellcode, `VirtualAlloc(RW)`, `memcpy`, `VirtualProtect(RX)`, `CreateThread`. Use a benign shellcode (e.g., MessageBox or calc.exe launcher) for safe testing.

**Files:** `tests/payloads/test_xll.cpp`

**Acceptance Criteria:** XLL compiles. When opened in Excel, it executes the benign shellcode successfully.

### P10-T2 — Attack Chain Automation `[L]`

**Task:** Create a test automation script that executes each attack phase and validates that the expected alerts fire. Phases: (1) drop XLL to disk, (2) open XLL in Excel, (3) establish outbound connection, (4) create preview handler registry persistence, (5) run .NET assembly, (6) open handle to `lsass.exe`, (7) enumerate SMB shares, (8) read target files.

**Files:** `tests/integration/attack_chain.ps1`

**Acceptance Criteria:** Script runs end-to-end. Each phase produces at least one alert in the agent log. A summary report shows phase → alert mapping.

### P10-T3 — Detection Rules for Attack Chain `[M]`

**Task:** Write detection rules (YAML) for each attack phase: suspicious Excel child process, shellcode injection sequence, novel outbound connection from Office process, preview handler COM registration, .NET assembly load from non-standard path, lsass handle access, internal SMB enumeration, sensitive file read + network exfil sequence.

**Files:** `rules/ch13_attack_chain.yaml`

**Acceptance Criteria:** Each rule fires correctly during the P10-T2 test run. No false positives from normal system activity during a 30-minute baseline test.

### P10-T4 — Test Report `[M]`

**Task:** Generate a test report: for each sensor (driver callbacks, hooks, minifilter, WFP, ETW, AMSI, scanner), list which attack phases it contributed telemetry to and which evasions from Chapters 2–12 it is known-vulnerable to. Output as a markdown file in `docs/`.

**Files:** `docs/test_report.md`, `tests/integration/report_generator.ps1`

**Acceptance Criteria:** Report covers all 8 attack phases. Each sensor has at least one known-vulnerable evasion documented. Report is accurate against actual test results.

---

## Phase 11: Hardening & Self-Protection

**Goal:** Implement tamper detection and evasion-resistance features. This is the "Advanced" tier work from Chapter 1, focused on detecting the book's own evasion techniques.

**Book reference:** Chapters 2–12 (evasion sections), Chapter 1 (bypass classifications).

### P11-T1 — Direct Syscall & ntdll Remapping Detection `[L]`

**Task:** Detect direct syscalls and ntdll remapping. In the hooking DLL, validate that hooked function return addresses point into known legitimate modules (not unbacked memory). Detect multiple mappings of `ntdll.dll` in the process (sign of ntdll remapping). Alert on both.

**Files:** `sentinel-hook/evasion_detect.c`

**Acceptance Criteria:** A test tool using direct syscalls (e.g., SysWhispers output) triggers a "syscall from unbacked memory" alert. A test tool that remaps ntdll triggers a "duplicate ntdll mapping" alert.

### P11-T2 — Hook Integrity Monitoring `[M]`

**Task:** Detect hook removal. Periodically (every 5s) verify that hooks are still in place by checking the first bytes of each hooked function against the expected JMP instruction. If hooks are removed, re-install and emit a tampering alert.

**Files:** `sentinel-hook/hook_integrity.c`

**Acceptance Criteria:** A test tool that overwrites hooked bytes with original ntdll bytes triggers a hook-tamper alert, and hooks are re-installed within 5 seconds.

### P11-T3 — Kernel Callback Tamper Detection `[XL]`

**Task:** Detect callback array tampering in the kernel. Periodically verify that the driver's registered callbacks are still present in the kernel callback arrays (`PspCreateProcessNotifyRoutine`, etc.). Emit alert if callbacks are missing. Also monitor for ETW trace session stops (detect trace-session tampering from Ch. 8).

**Files:** `sentinel-drv/self_protect.c`, `sentinel-drv/self_protect.h`

**Acceptance Criteria:** Using a test tool that removes kernel callbacks (similar to EDRSandblast) triggers a callback-tamper alert. Stopping the ETW trace session externally triggers a trace-tamper alert.

### P11-T4 — AMSI Bypass Detection `[M]`

**Task:** Detect AMSI bypass attempts. In the AMSI provider, periodically verify the integrity of `AmsiScanBuffer`'s first bytes in the loaded `amsi.dll`. Detect the common patch (`mov eax, 0x80070057; ret`). Alert on tampering.

**Files:** `sentinel-agent/amsi/amsi_integrity.cpp`

**Acceptance Criteria:** Running a standard AMSI bypass (AmsiScanBuffer patch) triggers an AMSI-tamper alert before subsequent scans are silently skipped.

### P11-T5 — Telemetry Cross-Validation `[M]`

**Task:** Implement telemetry cross-validation. Compare process-creation events from the kernel driver callback against events from the `Microsoft-Windows-Kernel-Process` ETW provider. Alert if events appear in one source but not the other (indicates sensor blinding).

**Files:** `sentinel-agent/crossvalidation.cpp`

**Acceptance Criteria:** Disabling the kernel callback (simulated by filtering out events) triggers a cross-validation alert when ETW still reports the process creation.

---

## Phase Summary & Dependency Map

| Phase | Name | Tasks | Depends On | Book Ch. | Tier |
|-------|------|-------|------------|----------|------|
| P0 | Project Scaffolding | 5 tasks | — | Ch. 1 | Foundation |
| P1 | Process/Thread Callbacks | 4 tasks | P0 | Ch. 3 | Basic |
| P2 | Object/Image/Registry | 4 tasks | P1 | Ch. 4–5 | Basic |
| P3 | Function-Hooking DLL | 4 tasks | P2 (KAPC) | Ch. 2 | Basic |
| P4 | Agent Service Core | 5 tasks | P1, P3 | Ch. 1 | Basic |
| P5 | Filesystem Minifilter | 4 tasks | P4 | Ch. 6 | Intermediate |
| P6 | Network Filter (WFP) | 3 tasks | P4 | Ch. 7 | Intermediate |
| P7 | ETW & AMSI | 4 tasks | P4 | Ch. 8, 10 | Intermediate |
| P8 | Scanner Engine | 3 tasks | P4, P5 | Ch. 9 | Intermediate |
| P9 | CLI & Config | 3 tasks | P4–P8 | Ch. 1 | Intermediate |
| P10 | Integration Testing | 4 tasks | All | Ch. 13 | Validation |
| P11 | Hardening | 5 tasks | All | Ch. 2–12 | Advanced |

**Total tasks:** 48 across 12 phases. Estimated 35–50 Claude Code sessions for complete implementation.

---

## Code Conventions & Constraints

### Kernel-Mode (sentinel-drv)

- Language: C17 (no C++ in kernel). No STL, no exceptions, no C runtime beyond what WDK provides.
- Memory: all allocations tagged with a 4-byte pool tag (e.g., `'SnPc'`). `ExAllocatePool2` preferred over deprecated `ExAllocatePoolWithTag`.
- IRQL: all callback code must document its expected IRQL. No `DISPATCH_LEVEL` code touching paged memory.
- Error handling: every `NTSTATUS` checked. All resources cleaned up in `DriverUnload` (callbacks unregistered, communication port closed, minifilter unregistered, WFP callouts removed).
- Driver Verifier: must pass standard Driver Verifier checks (pool tracking, IRQL checking, deadlock detection) under normal operation.

### User-Mode (sentinel-hook, sentinel-agent, sentinel-cli)

- `sentinel-hook`: C17 (DLL injected into arbitrary processes; minimize CRT dependency).
- `sentinel-agent`: C++20 with MSVC. Prefer Win32 API over CRT where performance matters.
- `sentinel-cli`: C++20. Keep dependencies minimal (no Boost, no heavy frameworks).
- All components: no external network calls. No telemetry phoning home. This is a local-only tool.
- Threading: use Windows thread pool (`CreateThreadpoolWork`) for async tasks. Named pipe I/O uses overlapped I/O.
- Logging: structured JSON to file. No `printf` to console except in CLI and test tools.

### Detection Rules (YAML)

- One rule per file, or grouped by ATT&CK tactic.
- Fields reference `telemetry.h` field names directly.
- Severity levels: `informational`, `low`, `medium`, `high`, `critical`.
- Actions: `LOG` (default), `BLOCK` (where sensor supports prevention), `DECEIVE` (future).

---

## v2 Roadmap: Remote Management & Multi-Host

v1 is intentionally local-only — all components run on a single test machine, telemetry writes to a local JSON log, and the CLI communicates with the agent over a local named pipe. This keeps the scope focused on sensor engineering and kernel-mode development.

v2 introduces remote management so the EDR can be installed on a test machine and monitored from an admin workstation.

### Planned v2 Components

**`sentinel-server`** — A new binary that runs on the admin/analyst machine. Responsibilities:

- TCP/TLS listener that accepts agent connections (mutual TLS with self-signed certs for lab use).
- Event ingestion and storage (SQLite for simplicity, or optionally forward to ELK/Splunk).
- REST API for querying alerts, telemetry, connection tables, and process state across enrolled agents.
- Agent enrollment and heartbeat tracking (which agents are alive, last check-in time).
- Optional: minimal web dashboard (single-page HTML/JS served by the REST API).

**Agent changes for v2:**

- `sentinel-agent` gains a configurable telemetry output mode: `local` (JSON file, same as v1), `remote` (TLS push to `sentinel-server`), or `both`.
- Agent authenticates to server on startup, sends heartbeats, and pushes telemetry events in batches.
- Local logging remains as a fallback if the server connection drops (buffer + retry).

**CLI changes for v2:**

- `sentinel-cli` gains a `--remote <server:port>` flag to connect to `sentinel-server` instead of the local named pipe.
- All existing commands (status, alerts, scan, connections, processes, hooks) work identically in remote mode — the CLI doesn't care whether data comes from a local pipe or a remote API.

### v2 Design Constraints

- Server is C++ (same toolchain as the agent). No Python, no Node — keeps the project self-contained.
- TLS only. No plaintext transport, even in lab environments.
- Multi-agent support: server tracks telemetry per-agent and the CLI can filter by agent hostname.
- No cloud dependencies. The server is a single binary with no external services required.

### v2 Architecture Preparation in v1

To make the v2 transition smooth, v1 already makes certain design decisions:

- All telemetry flows through the `SENTINEL_EVENT` struct and the `common/ipc` serialization layer. Adding a TLS transport is just a new output sink — the serialization format doesn't change.
- The named pipe protocol uses length-prefixed framing, which maps directly to a TCP stream protocol.
- The CLI's command interface is abstract enough that swapping the transport (named pipe → HTTP/REST) requires changes only in the transport layer, not in the command logic.
- The agent's event processing pipeline already decouples ingestion from output — adding a second output (network push alongside local file) is a pipeline fork, not a redesign.

### Other v2+ Candidates

- **ELAM driver and EtwTi consumer** (Ch. 11–12): requires Microsoft ELAM certificate. Explore after v1 validates the rest of the architecture.
- **Hypervisor-based detection** (Appendix): anti-exploit and anti-ransomware use cases.
- **Adversary deception** (Ch. 1 "Advanced" tier): return spoofed data to attackers instead of blocking.
- **RPC filters** (Appendix): DCSync and PetitPotam prevention.
- **Nirvana hooks** (Appendix): syscall return interception as a complement to inline hooks.