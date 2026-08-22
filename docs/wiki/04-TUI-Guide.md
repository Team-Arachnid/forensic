# 4 · Terminal UI Guide

[← CLI Reference](03-CLI-Reference.md) · [Home](Home.md) · [Next: Evidence Container →](05-Evidence-Container.md)

`arachnid-tui` is the second front end over the same engine. It drives the
library crates directly — it never shells out to `arachnid-core`, and it can do
nothing the CLI cannot. A container written by the TUI verifies with the CLI and
validates against the same published schemas.

```bash
arachnid-tui
# or, from the repository:
cargo run -p arachnid-core-tui
```

---

## Contents

- [Launch and the splash](#launch-and-the-splash)
- [The frame](#the-frame)
- [Global keys](#global-keys)
- [The eight screens](#the-eight-screens)
  - [1 · Dashboard](#1--dashboard)
  - [2 · Collect](#2--collect)
  - [3 · Capture](#3--capture)
  - [4 · Parse PCAP](#4--parse-pcap)
  - [5 · Verify](#5--verify)
  - [6 · Report](#6--report)
  - [7 · Sanitize](#7--sanitize)
  - [Chain of custody](#chain-of-custody)
- [Editing fields](#editing-fields)
- [Confirmations](#confirmations)
- [The operational log pane](#the-operational-log-pane)
- [Layout, colour and accessibility](#layout-colour-and-accessibility)
- [What the TUI does not expose](#what-the-tui-does-not-expose)
- [Persisted state](#persisted-state)
- [Crash safety](#crash-safety)

---

## Launch and the splash

On launch it shows the wordmark while it probes the host in the background:

- **effective privilege** — read from `/proc/self/status` on Linux,
  `IsUserAnAdmin()` on Windows;
- **capture availability** — whether the packet-capture library loads and any
  devices are visible.

```
                       /\   /\
                      (  o.o  )
                        > ^ <
               _.-'~~~~~~~~~~~~~~~'-._
               .'                   '.
               |      ARACHNID       |
               |  F O R E N S I C S  |
               '.___________________.'

                  ⠋ checking host…
              authorized DFIR use only
```

The splash shows for at least 900 ms and at most 1600 ms; it exits early once
the probes finish, and any key skips it after the minimum. Then the dashboard.

**A failed probe becomes a warning banner, never a refusal to start.** An
unprivileged operator can still verify and report on a container collected
elsewhere, and that is a legitimate thing to want to do.

Typical warnings:

```
not running elevated: collection will miss processes owned by other users,
and live capture will not open a device

no capture devices visible (needs root/CAP_NET_RAW on Linux, Npcap on Windows);
capture is unavailable
```

---

## The frame

```
 arachnid  1:Dashboard  2:Collect  3:Capture  4:Parse PCAP  5:Verify  6:Report  7:Sanitize
 ! not running elevated: collection will miss processes …  (Esc dismisses)
╭ privilege ─────────────╮╭ packet capture ────────╮╭ evidence session ──────╮
│root                    ││2 device(s)             ││./ev-host01             │
│full collection availab.││eth0, lo                ││operator analyst-7@linux│
│                        ││                        ││verified 8 artifacts    │
╰────────────────────────╯╰────────────────────────╯╰────────────────────────╯
 go to
 > Collect     collect volatile system state
   Capture     capture live network traffic
   Parse PCAP  analyse an existing PCAP
   Verify      verify an evidence container
   Report      render a container's report
   Sanitize    securely erase a device — destroys data
 no startup warnings; every check passed
 ? this help  ·  j/k move  ·  Enter open  ·  Tab next screen  ·  1-7 jump …
```

Five bands, top to bottom:

| Band | Height | Contents |
|---|---|---|
| header | 1 | tab strip, plus `[capturing]` while a capture runs |
| banner | 0–1 | the first startup warning, if any. Suppressed on the Dashboard (which prints them all in full) and below 12 rows |
| body | rest | the current screen |
| log pane | 0 or 9 | toggled with `Ctrl-L`; hidden below 18 rows |
| footer | 1 | the current screen's key hints |

---

## Global keys

Available from every screen.

| Key | Does |
|---|---|
| `Tab` | next screen |
| `Shift-Tab` | previous screen |
| `1`–`7` | jump to that screen |
| `?` | show every binding |
| `Ctrl-L` | toggle the operational log pane |
| `Esc` | dismiss a toast, leave a drill-down, or return to the Dashboard |
| `q` | quit (asks first if work is in flight) |

The keymap is a single table in the source. The help overlay renders it and the
dispatcher scans it, so **a binding cannot appear in the help without working,
or work without appearing** — there is a test asserting exactly that.

`Esc` walks back in a defined order: an open toast first, then the Custody
drill-down (returning to whichever screen opened it), then to the Dashboard.

---

## The eight screens

### 1 · Dashboard

Status at a glance, and a launcher.

**Cards:** privilege · packet capture availability and device list · current
evidence session (last container, operator, last verify result).

**Below:** the six quick-launch tiles, and every startup warning in full.

| Key | Does |
|---|---|
| `j` / `k` | move the selection |
| `Enter` | open the selected screen |

---

### 2 · Collect

Runs `collect` against the local host.

**Fields:** output directory · operator · signing key · hash-binaries toggle.

| Key | Does |
|---|---|
| `j` / `k` | move between fields |
| `Enter` | edit the field, or toggle hash-binaries |
| `r` | run the collection (asks first) |

While it runs you get a **live per-collector checklist** — the same five
collectors in the same order the CLI runs them, driven by a progress callback
rather than a guess, so the checklist cannot drift from the collection.

When it finishes: artifact counts per collector, the key fingerprint, and any
warnings.

---

### 3 · Capture

Runs a live packet capture.

**Fields:** device (chosen from the probed list) · output directory · BPF filter
· operator · signing key · promiscuous toggle.

| Key | Does |
|---|---|
| `j` / `k` | move between fields |
| `h` / `l` | previous / next capture device |
| `Enter` | edit the field, or toggle promiscuous |
| `s` | start or stop the capture (asks first) |

**The capture keeps running while you navigate.** It is a background thread; the
header shows `[capturing]` from every screen. Come back to this screen at any
time to see the counters.

**Live figures are counters only** — packets and bytes, published through plain
atomics. Decoding frames to fill a packet table would put per-frame work in the
capture loop, which is how a capture falls behind the link and drops evidence.

Once stopped, the savefile is flushed, sealed into the custody log, and then
**re-read read-only** to produce a flow and protocol breakdown for display. That
breakdown is display only: nothing from it is added to the container, because
`arachnid-core capture` does not add it either.

---

### 4 · Parse PCAP

Analyse an existing savefile. **Read-only analysis first, export second** —
which is the order an analyst actually works in.

**Fields:** pcap path · BPF filter · output directory · operator · signing key.
Recent PCAPs are offered under the path field.

| Key | Does |
|---|---|
| `j` / `k` | move between fields, or between rows in a result pane |
| `Enter` | edit the field, or run the analysis |
| `h` / `l` | switch between the flows pane and the indicators pane |
| `e` | export the analysis to an evidence container (asks first) |

Analysing produces nothing on disk. Only `e` mints evidence — and the source
file's digest is taken **at export time**, so the container binds the bytes as
they are when the evidence is created.

---

### 5 · Verify

Verify an evidence container.

| Key | Does |
|---|---|
| `j` / `k` | move between artifact rows |
| `h` / `l` | cycle through recent containers |
| `Enter` | edit the container path |
| `v` | verify |
| `c` | open the chain-of-custody view |

Shows a **per-artifact hash status** table, the overall verdict, and both the
collection time and the verify time — so the gap between them is visible.

---

### 6 · Report

Render and export a container's report.

**Fields:** container path · export path · format.

| Key | Does |
|---|---|
| `j` / `k` | move between fields |
| `Enter` | edit the field, or cycle the format |
| `o` | open the container |
| `x` | export |
| `c` | open the chain-of-custody view |

Format cycles `json → markdown → html → json`, the same three the CLI offers.
Shows the container's contents grouped by artifact type.

---

### 7 · Sanitize

**This screen destroys data.** Full reference:
[Secure Erasure](14-Secure-Erasure.md).

A four-step flow: **device list → method → confirm → progress**.

| Key | Does |
|---|---|
| `j` / `k` | select |
| `Enter` | next step |
| `Esc` | back a step |
| `r` | re-enumerate devices |
| `f` | permit system-disk wipes for this session |
| `d` | toggle dry run |
| `x` | cancel a running job |
| **`Shift-W`** | **commit the wipe** (confirm step only) |

**The commit key is deliberately `Shift-W`** — not `Enter`, and not `y`. Both of
those are what the ordinary confirmation dialog takes, and a wipe must not be
clearable by the reflex that clears those.

The device list **refuses to hand a system disk to the wipe flow** unless `f` is
set, so the operator never types a serial for a device they cannot wipe.
Pressing `f` raises an error-styled toast saying the override is active.

A **3-second cooldown** precedes the first write, and the commit key is
*rejected*, not merely ignored, until it elapses. Cancelling a running job asks
first, and says plainly that the device will be left partially overwritten and
will not be certified.

---

### Chain of custody

Reached with `c` from Verify or Report. Not a tab — a drill-down; `Esc` returns
to whichever screen opened it.

| Key | Does |
|---|---|
| `j` / `k` | move between records |
| `g` / `G` | first / last record |
| `Esc` | back |

Every record in order, with the selected one shown **in full**: the complete
digest, not a prefix. Nothing on that screen is summarized away — a chain of
custody you have to trust a truncation of is not one.

> The custody view **reads** the log; it does not validate it. Signatures and
> the hash chain are `verify`'s business. Use screen 5 for the verdict.

---

## Editing fields

Fields have an **explicit edit mode**, so a path containing `q` can actually be
typed.

| Key | Does |
|---|---|
| `Enter` | enter the field |
| *any character* | append |
| `Backspace` | delete the last character |
| `Ctrl-U` | clear the field |
| `Esc` or `Enter` | leave the field |

While editing, **global bindings stand down** — the field sees everything except
the way out. Changing screens always leaves edit mode, because carrying an edit
across screens would send keystrokes somewhere the operator is not looking.

---

## Confirmations

**Anything that starts, replaces or stops evidence collection asks first.**
Nothing that touches evidence happens on a single keypress.

| Action | Confirmed |
|---|---|
| Start a collection (`r`) | yes |
| Start or stop a capture (`s`) | yes |
| Export a PCAP analysis (`e`) | yes |
| Quit while a capture or job is running (`q`) | yes |

`y` / `Y` / `Enter` confirms, `n` / `N` / `Esc` cancels.

Confirming a quit **during a capture sets the stop flag** rather than dropping
the thread, so the savefile is flushed and sealed rather than lost. There is a
test asserting exactly this.

**One job at a time.** Starting a second while one runs is refused with a toast
(`collect is still running`); two concurrent runs would mean two containers with
interleaved custody timestamps.

Toasts clear themselves after six seconds, and `Esc` dismisses one early.

---

## The operational log pane

`Ctrl-L` toggles a nine-row pane showing the last lines of the `tracing` output.
Verbosity comes from `ARACHNID_LOG` (default `info`).

The buffer holds the last **1000 lines** — bounded because a chatty capture can
emit for hours and the pane is a debugging aid, not evidence.

Timestamps are omitted: the pane is narrow, and the timestamps that matter
forensically are in the container's custody log. This pane is **not** the
evidence log and is never written into a container.

Below 18 rows the pane is suppressed — it is the first thing to go when there is
no room, because the screen under it is the work.

---

## Layout, colour and accessibility

- **`NO_COLOR` is respected**, per [no-color.org](https://no-color.org): set and
  non-empty means monochrome, whatever the terminal claims to support.
- **Every verdict is stated in text as well as colour**, so nothing is lost in a
  monochrome terminal or to a colour-blind reader. "VERIFIED" is a word, not a
  green box.
- **Layout degrades rather than breaks** down to **32×8**: the tab strip
  collapses to a position indicator, cards lose their borders, tables truncate
  with a `… n more` marker, the log pane and banner disappear.
- Below 32×8 it prints `terminal too small / needs 32x8` rather than drawing
  something corrupt.
- The test suite renders **every screen at every supported size** with every
  overlay combination, so a layout that would panic and take the terminal with
  it fails in CI instead of on a responder's laptop.

---

## What the TUI does not expose

The TUI covers the common path. These CLI options have no field on any screen —
use `arachnid-core` for them:

| Not in the TUI | Use |
|---|---|
| Memory acquisition | `--memory-tool`, `--memory-tool-sha256`, `--memory-arg` |
| Dry run | `--dry-run` |
| Skipping binary hashing | `--no-hash-binaries` |
| Capture stop conditions | `--duration`, `--count` |
| Capture frame size | `--snaplen` |
| Reassembly ceiling | `--max-stream-bytes` |
| Log destination and level | `--log`, `--log-level` (the TUI reads `ARACHNID_LOG`) |

This is a deliberate subset, not a gap to be filled: the TUI is a view and
controller layer with no engine logic of its own.

---

## Persisted state

The TUI remembers the operator name and recent paths in:

| Platform | Path |
|---|---|
| Linux (XDG) | `$XDG_STATE_HOME/arachnid/tui-state.json` |
| Linux (fallback) | `~/.local/state/arachnid/tui-state.json` |
| Windows | `%APPDATA%\arachnid\tui-state.json` |

Contents: operator name, last container, and up to eight recent PCAPs and
containers, plus the last verify result.

**That file is a convenience, never evidence.** Deleting it costs two retyped
paths. A write failure becomes a debug log line and nothing else — a UI
convenience file is never worth failing a run over.

---

## Crash safety

A panic hook restores the terminal — raw mode off, alternate screen left —
**before** the panic message prints. A crash cannot leave your shell unusable,
and the backtrace lands somewhere you can read it.

---

[← CLI Reference](03-CLI-Reference.md) · [Home](Home.md) · [Next: Evidence Container →](05-Evidence-Container.md)
