# Build Prompt: Arachnid Core — Live Triage & Network Forensics Engine

Use this as a project spec / prompt for a coding assistant (e.g. Claude Code) to scaffold and build the tool.

---

## Prompt

You are building **Arachnid Core**, the live triage and network forensics module of a larger suite called Arachnid Forensic. This is a legitimate DFIR (Digital Forensics & Incident Response) tool intended for use by authorized analysts on systems they have permission to examine. Build it to production quality, not as a prototype.

### Language & Platform

- Primary language: **Rust** (stable toolchain, 2021 edition).
- Target platforms: Windows 10/11 and Linux (Ubuntu/RHEL family) via conditional compilation. macOS support is a stretch goal, not a blocker.
- Compile to a single statically linked binary per platform (musl target on Linux, static CRT on Windows). No runtime interpreter, no bundled scripting engine.
- No packing, obfuscation, or anti-analysis techniques of any kind. The binary's behavior must be fully inspectable via standard tools (`strings`, disassemblers, `sigcheck`). This is a deliberate design constraint, not an oversight — analysts and SOC teams must be able to verify what the tool does before allowlisting it.

### Core Architecture

Structure as a Cargo workspace with these crates:

- `arachnid-core-cli` — command-line entrypoint and argument parsing (use `clap`).
- `arachnid-collect` — volatile data collectors (processes, network state, users, drivers/modules, autoruns/persistence locations).
- `arachnid-netcap` — live packet capture and offline PCAP parsing (bind to `libpcap`/`npcap` via `pcap` crate; protocol parsing via `etherparse` or similar).
- `arachnid-evidence` — evidence container format: hashing, timestamping, signing, chain-of-custody log.
- `arachnid-report` — structured output generation (JSON/YAML schema, human-readable summary).

### Functional Requirements

**1. Volatile data collection (memory-safe, read-only against the live system):**

- Running processes with full command line, parent PID, loaded modules, hashes of on-disk binaries where resolvable.
- Open network connections (TCP/UDP, listening + established) mapped to owning process.
- Logged-in/active user sessions.
- Loaded kernel drivers / kernel modules.
- Common persistence locations (Run keys, scheduled tasks, systemd units, cron, LaunchAgents) — enumerate and record, do not modify.
- Every collector must be read-only against the target system. No writes outside the designated evidence output directory.

**2. Memory acquisition:**

- Do not write a custom kernel-mode memory driver. Wrap and invoke an existing, vetted acquisition tool (e.g., WinPmem on Windows, AVML on Linux) as a subprocess, verify its own binary hash before invoking it, and capture its output into the evidence container.

**3. Network forensics:**

- Live capture mode: start/stop capture with BPF filter support, write to standard PCAP/PCAPNG.
- Offline mode: parse an existing PCAP/PCAPNG, reconstruct TCP streams, extract observable indicators (IPs, domains from DNS/TLS SNI, HTTP hosts/URIs) into a structured indicator list.
- No active packet injection or man-in-the-middle capability — capture and parse only.

**4. Evidence integrity (chain of custody by design):**

- Every artifact collected is SHA-256 hashed at the moment of collection.
- Each collection run produces an append-only, cryptographically signed log (Ed25519) recording: what was collected, when (UTC + monotonic clock), by which operator/context, and the hash of each artifact.
- Evidence container is tamper-evident: any post-collection modification to an artifact must be detectable by re-verifying against the signed log.
- Provide a separate `arachnid-core verify <container>` command that re-hashes all artifacts and checks them against the signed log, independent of the collection code path.

**5. Low-false-positive-footprint engineering (legitimate operational security, not evasion):**

- Static linking, minimal dependency tree (audit with `cargo audit` / `cargo deny`), reproducible builds.
- Code-signing pipeline (Authenticode on Windows, detached GPG signature on Linux) as part of the release process.
- Ship a "SOC allowlisting guide" doc: binary hashes per release, expected file/registry/network touchpoints, so defenders can pre-approve the tool rather than the tool trying to hide from them.
- No dynamic code loading, no self-modification, no encrypted/obfuscated payloads, no disabling of AV/EDR services, no process injection. These are hard constraints — treat any design that requires them as out of scope and flag it instead of implementing it.

**6. CLI/UX:**

- Subcommands: `collect`, `capture`, `parse-pcap`, `verify`, `report`.
- `--dry-run` mode on anything that touches disk.
- Structured logging (`tracing` crate) to a separate operational log, distinct from the evidence log.
- Exit codes and errors must be scriptable (for use in larger IR playbooks / SOAR pipelines).

### Output

- Primary output: schema-versioned JSON (documented JSON Schema shipped alongside).
- Secondary: human-readable Markdown/HTML summary for quick analyst review.
- Output designed to be consumed downstream by the Arachnid Recover module (same evidence container format).

### Non-Goals (explicitly out of scope — do not implement)

- Anti-EDR, anti-AV, or anti-debugging techniques of any kind.
- Any form of packing, encryption of the binary itself, or runtime obfuscation.
- Exploit code, privilege escalation, or any capability beyond read-only collection with documented OS APIs.
- Persistence mechanisms for the tool itself.

### Deliverables

1. Working Cargo workspace with the crate structure above, compiling cleanly on Windows + Linux.
2. Unit tests per collector (mockable OS interfaces so tests run without root/admin where possible) and integration tests against a disposable VM/container.
3. `cargo audit`/`cargo deny` clean dependency tree.
4. README with build instructions, threat model, and the SOC allowlisting guide.
5. JSON Schema for the evidence/report format.
6. A signed sample release build with SHA-256 checksums published.

Start by scaffolding the workspace and the `arachnid-evidence` crate first, since every other module depends on its hashing/signing/logging API.
