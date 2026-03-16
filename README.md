# SentinelEDR

<p align="center">
  <img src="docs/logo.jpg" alt="SentinelEDR Logo" width="400">
</p>

A proof-of-concept Endpoint Detection & Response (EDR) agent for Windows x64, built from the ground up with kernel-mode telemetry, user-mode API hooking, YARA scanning, and a multi-layer detection engine.

Architecture derived from sensor models in *Evading EDR* by Matt Hand (No Starch Press, 2023).

---

## What Is an EDR?

An **Endpoint Detection and Response** (EDR) agent is software that runs on every endpoint (workstation, server, laptop) in an environment to continuously monitor system activity, detect malicious behavior, and provide the data security teams need to investigate and respond to threats.

### Why EDR Matters

Traditional antivirus relies on static file signatures — it can only catch what it already knows about. Adversaries bypass this trivially with packers, obfuscation, and fileless techniques. EDR takes a fundamentally different approach:

- **Deep visibility.** EDR instruments the operating system at every layer — kernel callbacks, API hooks, ETW traces, script inspection — to capture *what actually happens* on a host, not just what files exist on disk. This telemetry covers process creation, memory operations, registry changes, network connections, DLL loads, and more.

- **Behavioral detection.** Instead of matching file hashes, EDR watches sequences of actions. A single `VirtualAllocEx` call is normal; `VirtualAllocEx(RW)` → `VirtualProtect(RX)` → `CreateRemoteThread` in rapid succession is a classic shellcode injection pattern. EDR correlates these events in real time.

- **Post-compromise investigation.** When an incident occurs, the EDR's telemetry log becomes the forensic record. Analysts can reconstruct the full attack chain — initial access, lateral movement, persistence, data staging — without relying on the attacker to leave artifacts behind.

- **Threat hunting.** Security practitioners proactively query EDR telemetry to search for techniques and indicators that automated rules haven't flagged. The richer the telemetry, the more effective the hunt.

### Who Uses EDR

| Role | How They Use EDR |
|------|------------------|
| **SOC Analyst** | Triages alerts, investigates detections, determines scope of compromise |
| **Incident Responder** | Reconstructs attack timelines from telemetry, identifies affected hosts |
| **Threat Hunter** | Queries historical telemetry for TTPs and IOCs across the fleet |
| **Detection Engineer** | Writes and tunes behavioral rules based on ATT&CK techniques |
| **Red Teamer** | Studies EDR internals to understand defensive coverage and gaps |

### Why Build One?

Understanding how an EDR works at the implementation level — kernel callbacks, inline hooks, filter drivers, ETW plumbing — is the fastest way to understand both what defenders can see and what attackers try to evade. SentinelPOC exists for exactly this purpose: a fully transparent, source-available EDR that security practitioners can study, modify, and experiment with.

---

## What It Does

SentinelPOC instruments a Windows system at every layer — kernel callbacks, inline API hooks, ETW tracing, AMSI integration, and file system filtering — to collect security telemetry and detect adversary techniques in real time.

**Highlights:**

- **Kernel-mode driver** with process, thread, object, image-load, registry, file I/O, network, and named pipe callbacks
- **Automatic DLL injection** via kernel APC into every new process for user-mode API hook coverage
- **13 hooked ntdll/kernel32 functions** capturing memory allocation, process injection, and thread creation
- **8 ETW providers** for .NET assembly loads, PowerShell script blocks, DNS queries, Kerberos auth, RPC calls, and more
- **Custom AMSI provider** that scans PowerShell/VBScript/JScript content against YARA rules
- **On-access YARA scanning** triggered by minifilter file events with hash-based caching
- **Memory scanning** for unbacked executable regions (shellcode injection detection)
- **Three-tier detection engine**: single-event rules, time-ordered sequence rules, and threshold-based alerting
- **14 YARA rules** detecting Cobalt Strike, Mimikatz, packed binaries, suspicious PE characteristics, and XLL shellcode
- **Git-based rule updates** with dry-run validation and automatic rollback on failure
- **CLI management tool** for real-time status, alerts, process inspection, network connections, and configuration queries
- **INI-style configuration file** with runtime-tunable paths, scanner limits, and thresholds
- **JSON-lines telemetry logging** with automatic rotation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL MODE                              │
│                                                                 │
│  sentinel-drv.sys                                               │
│  ├── Process/Thread callbacks ─────┐                            │
│  ├── Object callbacks (LSASS       │                            │
│  │   protection)                   │   Filter Communication     │
│  ├── Image-load + KAPC injection   ├──── Port ──────────┐       │
│  ├── Registry callbacks            │                    │       │
│  ├── Minifilter (file I/O + hash)  │                    │       │
│  ├── Named pipe monitoring         │                    │       │
│  └── WFP callout (network)  ──────┘                    │       │
└─────────────────────────────────────────────────────────│───────┘
                                                         │
┌─────────────────────────────────────────────────────────│───────┐
│                        USER MODE                        │       │
│                                                         ▼       │
│  sentinel-agent.exe                                             │
│  ├── Driver Port Receiver ◄────────────────────────────┘        │
│  ├── Pipe Server ◄──────────── sentinel-hook.dll (per-process)  │
│  ├── ETW Consumer ◄─────────── 8 system providers               │
│  ├── AMSI Provider ◄────────── PowerShell / script hosts        │
│  │                                                              │
│  ├── Event Queue ──► Processing Thread                          │
│  │                    ├── Process table enrichment               │
│  │                    ├── On-access YARA scanner                 │
│  │                    ├── Memory scanner (unbacked regions)      │
│  │                    ├── Single-event rule engine               │
│  │                    ├── Sequence rule engine                   │
│  │                    ├── Threshold rule engine                  │
│  │                    └── JSON log writer (auto-rotate)          │
│  │                                                              │
│  ├── Command Handler ◄──────── sentinel-cli.exe (named pipe)    │
│  └── Config Loader ◄──────── sentinel.conf (INI-style)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **sentinel-drv** | C17 (WDK) | Kernel-mode WDM driver with 8 callback types, minifilter, WFP callout, and KAPC injection |
| **sentinel-hook** | C17 | User-mode hooking DLL injected via kernel APC. Inline hooks on 13 ntdll/kernel32 functions |
| **sentinel-agent** | C++20 | Windows service: event aggregation, rule engines, ETW consumer, AMSI provider, YARA scanner, config loader |
| **sentinel-amsi** | C++20 | AMSI provider DLL registered with Windows for script content scanning |
| **sentinel-cli** | C++20 | Console management tool: status, alerts, scanning, process/connection inspection, config queries |

---

## CLI Commands

```
sentinel-cli <command> [args] [--json]
```

| Command | Description |
|---------|-------------|
| `status` | Agent health, driver status, uptime, rule counts, queue depth |
| `alerts [N]` | Show last N alerts with severity, rule name, trigger, and PID (default: 20) |
| `scan <path>` | Trigger on-demand YARA scan on a file |
| `rules reload` | Hot-reload behavioral and YARA rules from disk |
| `rules update` | Git pull latest rules, validate, and hot-reload (rollback on failure) |
| `rules update --init` | Clone rule repos for first-time setup (requires `--rules-repo` and `--yara-repo`) |
| `connections` | Network connection table: remote IP, port, protocol, hit count, PIDs |
| `processes` | Tracked processes with PPID, integrity level, elevation status |
| `hooks` | Hook DLL injection status per tracked process |
| `config` | Show active agent configuration (paths, scanner limits, thresholds) |

Add `--json` to any command for raw JSON output suitable for scripting and SIEM ingestion.

### Rules Update Workflow

The `rules update` command provides a safe, one-command workflow for deploying signature updates:

```powershell
# First-time setup: clone rule repositories
sentinel-cli rules update --init --rules-repo https://github.com/org/rules.git --yara-repo https://github.com/org/yara-rules.git

# Subsequent updates: pull, validate, reload
sentinel-cli rules update
```

The update process:
1. Saves current HEAD SHA for rollback
2. Runs `git pull --ff-only` on both rule directories
3. Sends validate-and-reload command to the agent
4. Agent dry-run parses all rules (detection + YARA) without activating
5. On success: hot-reloads rules into the running agent
6. On failure: CLI rolls back via `git reset --hard` — old rules remain active

YARA files using unsupported modules (e.g., `cuckoo`, `androguard`) are automatically skipped during compilation, allowing compatibility with community rulesets like [Yara-Rules](https://github.com/Yara-Rules/rules).

---

## Configuration

The agent reads an INI-style config file at startup. Default location: `C:\SentinelPOC\sentinel.conf`. Override with `--config <path>`.

Missing keys or a missing file gracefully fall back to compiled-in defaults.

```ini
[paths]
log_path        = C:\SentinelPOC\agent_events.jsonl
amsi_dll        = C:\SentinelPOC\sentinel-amsi.dll
rules_dir       = C:\SentinelPOC\rules
yara_rules_dir  = C:\SentinelPOC\yara-rules

[scanner]
max_file_size_mb   = 50      # Max file size for on-access YARA scan
max_region_size_mb = 10      # Max memory region size for memory scanner
cache_ttl_sec      = 300     # Scan result cache lifetime (seconds)

[logging]
max_log_size_mb = 100        # Log rotation threshold

[network]
max_events_per_sec = 100     # Per-PID network event rate limit

[git]
# rules_repo_url = https://github.com/org/sentinel-rules.git
# yara_rules_repo_url = https://github.com/org/sentinel-yara-rules.git
```

Query the running agent's active config with `sentinel-cli config`.

---

## Telemetry Sources

| Source | Origin | What It Captures |
|--------|--------|------------------|
| Process | Driver callback | Process creation/termination, image path, command line, SID, integrity level |
| Thread | Driver callback | Thread creation/termination, remote thread detection |
| Object | Driver callback | Handle operations on protected processes (lsass, csrss, services) |
| ImageLoad | Driver callback | DLL/EXE loads with signature validation |
| Registry | Driver callback | Key create/open, value set/delete (noise-filtered) |
| File | Minifilter | File create/write/rename/delete with SHA-256 hash |
| Network | WFP callout | Inbound/outbound connections, rate-limited per PID |
| Pipe | Minifilter | Named pipe creation with suspicious pipe detection |
| HookDll | Inline hooks | 13 API calls: memory ops, thread ops, process open, pipe create |
| ETW | 8 providers | .NET assemblies, PowerShell scripts, DNS, Kerberos, RPC, services, kernel process |
| AMSI | COM provider | Script content scanned by PowerShell/VBScript/JScript hosts |
| Scanner | YARA engine | On-access file scan and memory region scan results with rule match details |

---

## Detection Capabilities

### YARA Rules (14 rules across 5 files)

| File | Rules | Detects |
|------|-------|---------|
| `cobaltstrike_beacon.yar` | 3 | Beacon config blocks, shellcode stagers, default pipe names |
| `mimikatz.yar` | 3 | Binary builds, PowerShell ports (Invoke-Mimikatz), kernel driver (mimidrv) |
| `suspicious_pe.yar` | 4 | RWX sections, injection imports, packer section names, high-entropy sections |
| `upx_packed.yar` | 2 | Standard and modified UPX packing |
| `xll_shellcode.yar` | 2 | Excel XLL add-ins with shellcode stagers or injection imports |

### Behavioral Detection Rules (5 rules, 3 types)

| Rule | Type | ATT&CK | Trigger |
|------|------|--------|---------|
| Suspicious RWX Allocation | Single | T1055 | Cross-process `NtAllocateVirtualMemory` with `PAGE_EXECUTE_READWRITE` |
| Remote Thread Creation | Single | T1055.003 | `NtCreateThreadEx` targeting a different process |
| Excel Spawns cmd.exe | Single | T1059.003 | `cmd.exe` child process of `excel.exe` |
| Shellcode Runner Pattern | Sequence | T1055 | Alloc(RW) → Protect(RX) → CreateThread within 5 seconds |
| Rapid Memory Allocation | Threshold | — | ≥500 `NtAllocateVirtualMemory` calls in 10 seconds from one process |

---

## Hooked Functions

The hooking DLL intercepts 13 ntdll/kernel32 functions via inline hooks:

| Category | Functions |
|----------|-----------|
| **Memory** | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtCreateSection` |
| **Thread** | `NtCreateThreadEx`, `NtQueueApcThread`, `NtSuspendThread`, `NtResumeThread` |
| **Process** | `NtOpenProcess` |
| **Pipe** | `NtCreateNamedPipeFile` |

---

## Building

### Prerequisites

- **Visual Studio 2022** with the C++ desktop development workload
- **CMake 3.20+**
- **Windows Driver Kit (WDK)** — required for the kernel driver; user-mode components build without it

### Configure & Build

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

If WDK is not installed, `sentinel-drv` is skipped automatically. All other components build normally.

Output binaries land in `build/bin/Release/`:
- `sentinel-agent.exe` — the main agent service
- `sentinel-cli.exe` — management CLI
- `sentinel-drv.sys` — kernel driver (requires WDK)
- `sentinel-hook.dll` — hooking DLL (injected by driver)
- `sentinel-amsi.dll` — AMSI provider (registered by agent)

### Test Signing (required for driver deployment)

```powershell
# Enable test signing on the VM (requires reboot)
.\scripts\setup-testsigning.ps1

# Sign the driver
.\scripts\sign-driver.ps1
```

> **Warning:** Only enable test signing on isolated test VMs. Never on production systems.

---

## Deployment

### 1. Prepare the deployment directory

```powershell
# Create the deployment directory
New-Item -ItemType Directory -Force -Path C:\SentinelPOC

# Copy binaries
Copy-Item build\bin\Release\sentinel-agent.exe C:\SentinelPOC\
Copy-Item build\bin\Release\sentinel-cli.exe   C:\SentinelPOC\
Copy-Item build\bin\Release\sentinel-hook.dll   C:\SentinelPOC\
Copy-Item build\bin\Release\sentinel-amsi.dll   C:\SentinelPOC\

# Copy configuration
Copy-Item sentinel.conf                         C:\SentinelPOC\

# Copy rules
Copy-Item -Recurse rules\       C:\SentinelPOC\rules\
Copy-Item -Recurse yara-rules\  C:\SentinelPOC\yara-rules\
```

### 2. Install and start the kernel driver

```powershell
# Copy the signed driver
Copy-Item build\bin\Release\sentinel-drv.sys C:\SentinelPOC\

# Create the driver service
sc.exe create SentinelDrv type=kernel binPath="C:\SentinelPOC\sentinel-drv.sys"

# Start the driver
sc.exe start SentinelDrv
```

### 3. Run the agent

**Console mode** (recommended for testing):

```powershell
# Run from an elevated command prompt
C:\SentinelPOC\sentinel-agent.exe --console
```

With a custom config file:

```powershell
C:\SentinelPOC\sentinel-agent.exe --console --config C:\SentinelPOC\sentinel.conf
```

The agent will:
1. Load configuration from `sentinel.conf` (or use defaults)
2. Load YAML detection rules from the configured rules directory
3. Compile YARA rules from the configured YARA rules directory
4. Connect to the kernel driver's filter communication port
5. Start the named pipe server for hook DLL telemetry
6. Initialize ETW consumers for 8 system providers
7. Register the custom AMSI provider
8. Begin processing events and writing to the JSON log

Press **Ctrl+C** to stop cleanly.

**Service mode** (for persistent deployment):

```powershell
sc.exe create SentinelAgent binPath="C:\SentinelPOC\sentinel-agent.exe" start=auto
sc.exe start SentinelAgent
```

### 4. Verify operation

With the agent running, open a second terminal:

```powershell
# Check agent health
C:\SentinelPOC\sentinel-cli.exe status

# View active configuration
C:\SentinelPOC\sentinel-cli.exe config

# List tracked processes
C:\SentinelPOC\sentinel-cli.exe processes

# View network connections
C:\SentinelPOC\sentinel-cli.exe connections

# Check recent alerts
C:\SentinelPOC\sentinel-cli.exe alerts
```

---

## Testing On-Access Scanning

To verify YARA on-access scanning is working:

```cmd
:: From an elevated cmd.exe (not PowerShell — AMSI will block the strings)
echo sekurlsa:: kerberos:: lsadump:: privilege:: logonPasswords > C:\Users\%USERNAME%\Desktop\evil.txt
```

Within a few seconds the agent console should display:

```
[NNN] source=Scanner type=OnAccess path=C:\Users\...\evil.txt match=YES rule=Mimikatz_Binary
```

The minifilter detects the file creation, computes a SHA-256 hash, and the on-access scanner runs YARA rules against the file. Results are cached (configurable via `cache_ttl_sec`) to avoid redundant rescans.

---

## Project Structure

```
claude-edr/
├── CMakeLists.txt              Top-level build configuration
├── sentinel.conf               Default agent configuration file
├── common/                     Shared headers
│   ├── telemetry.h            Event schema (SENTINEL_EVENT union)
│   ├── constants.h            System-wide constants
│   ├── ipc.h                  Named pipe protocol + command types
│   └── ipc_serialize.h        Binary serialization helpers
├── sentinel-drv/              Kernel-mode driver
│   ├── main.c                 DriverEntry, cleanup, unload
│   ├── callbacks_process.c    PsSetCreateProcessNotifyRoutineEx
│   ├── callbacks_thread.c     PsSetCreateThreadNotifyRoutineEx
│   ├── callbacks_object.c     ObRegisterCallbacks
│   ├── callbacks_image.c      PsSetLoadImageNotifyRoutineEx
│   ├── callbacks_registry.c   CmRegisterCallbackEx
│   ├── minifilter.c           FltRegisterFilter (file I/O)
│   ├── minifilter_pipes.c     Named pipe creation monitoring
│   ├── wfp_callout.c          WFP network callout
│   ├── kapc_inject.c          Kernel APC DLL injection
│   └── file_hash.c            SHA-256 file hashing
├── sentinel-hook/             User-mode hooking DLL
│   ├── main.c                 DllMain, hook installation
│   ├── hook_engine.c          Inline hook framework
│   ├── hooks_memory.c         Memory operation hooks
│   ├── hooks_thread.c         Thread operation hooks
│   ├── hooks_process.c        Process operation hooks
│   └── pipe_client.c          Named pipe telemetry sender
├── sentinel-agent/            Agent service
│   ├── main.cpp               Entry point (--console, --config)
│   ├── service.cpp            SCM handler + console mode
│   ├── config.cpp             INI config parser + serializer
│   ├── config.h               SentinelConfig struct + API
│   ├── pipeline.cpp           Event queue + receiver threads
│   ├── event_processor.cpp    Event routing + enrichment
│   ├── cmd_handler.cpp        CLI command dispatch (9 commands)
│   ├── json_writer.cpp        JSON-lines log output + rotation
│   ├── network_table.cpp      Connection tracking table
│   ├── scanner/
│   │   ├── yara_scanner.cpp   libyara integration
│   │   ├── onaccess_scanner.cpp  File event → YARA scan
│   │   └── memory_scanner.cpp Unbacked region detection
│   ├── rules/
│   │   ├── rule_engine.cpp    Single-event rule evaluation
│   │   ├── sequence_engine.cpp  Time-ordered sequence detection
│   │   ├── threshold_engine.cpp  Count-based alerting
│   │   ├── rule_parser.cpp    YAML rule loading
│   │   └── rule_validator.cpp Dry-run rule validation
│   ├── etw/
│   │   └── etw_consumer.cpp   ETW trace session + 8 providers
│   └── amsi/
│       └── amsi_provider.cpp  Custom AMSI COM provider
├── sentinel-amsi/             AMSI provider DLL host
├── sentinel-cli/              CLI management tool
│   └── main.cpp               9 commands + git operations + pretty-printers
├── yara-rules/                YARA detection rules (14 rules)
├── rules/                     YAML behavioral rules (5 rules)
├── tests/                     Integration tests
├── scripts/                   Setup and signing scripts
├── deps/                      External dependencies (libyara)
├── cmake/                     CMake modules (FindWdk)
└── certs/                     Test signing certificates
```

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project scaffolding, build system, shared headers | Done |
| P1 | Process and thread kernel callbacks | Done |
| P2 | Object, image-load, and registry callbacks + KAPC injection | Done |
| P3 | User-mode hooking DLL with 13 inline hooks | Done |
| P4 | Agent service with event pipeline and 3-tier rule engine | Done |
| P5 | Minifilter, file hashing, and named pipe monitoring | Done |
| P6 | WFP network callout and connection table | Done |
| P7 | ETW consumer (8 providers) and custom AMSI provider | Done |
| P8 | YARA scanner integration, on-access scanning, memory scanning | Done |
| P9 | CLI management tool, inspection commands, configuration file | Done |
| P10 | Integration testing (end-to-end attack chain) | Pending |
| P11 | Hardening and self-protection (evasion detection) | Pending |

See `REQUIREMENTS.md` for the full implementation roadmap.

---

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is an educational proof-of-concept built for learning and research purposes. It is **not** production security software. Deploy only in authorized, isolated test environments.

## Acknowledgments

- *Evading EDR* by Matt Hand (No Starch Press, 2023) — the architectural reference for this project
- [YARA](https://virustotal.github.io/yara/) — pattern matching engine
- [MITRE ATT&CK](https://attack.mitre.org/) — technique references for detection rules
