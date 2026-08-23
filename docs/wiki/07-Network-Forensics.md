---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 7 · Network Forensics

[← Collectors](06-Collectors.md) · [Home](Home.md) · [Next: Reports & Schemas →](08-Reports-and-Schemas.md)

Live capture and offline analysis. **Capture and parse only.** The crate opens
capture handles and reads savefiles; it never transmits. No injection, no ARP or
DNS spoofing, no interception. The capture library's send path is never called —
out of scope by design, not by omission.

---

## Contents

- [Live capture](#live-capture)
- [BPF filters](#bpf-filters)
- [Drops](#drops-are-a-finding)
- [Stopping cleanly](#stopping-cleanly)
- [Offline analysis](#offline-analysis)
- [Link types](#link-types)
- [Flows](#flows)
- [TCP reassembly](#tcp-reassembly)
- [Indicators](#indicators)
- [Windows and Npcap](#windows-and-npcap)
- [Limitations](#limitations)

---

## Live capture

```bash
sudo arachnid-core capture -o ./ev-net -d eth0 -f "tcp port 443" --duration 300
```

Needs root or `CAP_NET_RAW` on Linux, Npcap driver access on Windows.

### How the capture loop works

The handle is opened with:

- **snaplen** `65535` by default — full frames, because a truncated payload is a
  truncated indicator;
- **promiscuous off** by default;
- **read timeout 250 ms** and **immediate mode**, then set to non-blocking.

The bounded timeout is why `Ctrl-C` works on an idle link: without it the loop
would block in the driver until the next packet arrived. On no-packet returns it
sleeps 20 ms rather than spinning.

Each iteration checks, in order: the stop flag, the packet limit, the duration —
then reads one packet, writes it to the savefile, and updates the counters.

`stop_reason` in the output records which one fired:
`interrupted by operator`, `packet limit reached`, or `duration elapsed`.

### Counters, not packets

A front end gets running totals — packets and bytes — through plain atomics,
not a channel of decoded packets.

> The capture loop must not do per-packet work on behalf of a UI. Falling behind
> the link drops evidence. Counters are the most a display can be given for
> free; packet detail comes from re-reading the savefile once it is closed and
> sealed.

That is why the TUI's live capture screen shows numbers, and the flow breakdown
only appears after the capture stops.

---

## BPF filters

`-f/--filter` takes standard [pcap-filter
syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html), the same language
`tcpdump` uses.

```bash
-f "tcp port 443"
-f "tcp port 443 and not host 10.0.0.1"
-f "not port 22"                       # exclude your own SSH session
-f "host 192.0.2.10 or host 192.0.2.11"
-f "net 10.0.0.0/8 and not net 10.1.0.0/16"
-f "udp port 53"                       # DNS only
-f "tcp[tcpflags] & tcp-syn != 0"      # SYNs
```

**Filters are compiled and applied in the kernel.** Excluded traffic is never
copied into userspace: not in the savefile, not in RAM, not in scope. That
matters when the exclusion is legally required rather than merely convenient —
you can state that the traffic was never collected, not merely discarded.

An invalid filter fails at open time with the filter text in the error:

```
error: apply BPF filter "tcp portt 443": syntax error
```

The same syntax applies to `parse-pcap -f`, where it is applied while reading the
savefile.

### Excluding your own session

Always worth doing. Your SSH or RDP session to the host is not evidence, and it
is noisy:

```bash
sudo arachnid-core capture -o ./ev-net -d eth0 -f "not port 22" --duration 600
```

---

## Drops are a finding

```
- ⚠ **Dropped 1204 (kernel) / 0 (interface) — this capture has gaps.**
```

Two counters, from `pcap_stats`:

| Counter | Means |
|---|---|
| `packets_dropped_kernel` | the kernel buffer overflowed — userspace did not keep up |
| `packets_dropped_interface` | the driver or NIC dropped before the kernel saw it |

Non-zero on either sets **exit code 4**, emits a `WARN` line, and adds a custody
note:

```
capture dropped 1204 kernel / 0 interface packets; evidence has gaps
```

**A capture with drops has holes in it, and holes in evidence must be visible.**
Never present a lossy capture as a complete record of the traffic.

Remedies, in order of effectiveness:

1. **Tighten the BPF filter.** Kernel-side filtering is free; everything else is
   not.
2. **Lower `--snaplen`.** 1500 or even 256 is plenty if you only need headers
   and indicators — but it truncates payloads, so reassembly and HTTP/TLS
   parsing suffer.
3. **Capture to faster storage.** A USB stick is a common culprit.
4. **Capture for shorter windows**, repeatedly.

---

## Stopping cleanly

`Ctrl-C` sets a flag; it does not kill the process. The loop notices, exits, and
then:

1. flushes the savefile,
2. closes it,
3. reads `pcap_stats` for the drop counters,
4. hashes the file and seals it into the custody log,
5. writes the report.

**Losing a capture to an abrupt exit would be losing evidence.** The same
applies in the TUI: quitting mid-capture asks for confirmation, and confirming
sets the stop flag rather than dropping the thread.

If the capture library returns a hard error mid-run, the savefile is still
flushed before the error propagates — you keep what was captured up to that
point.

---

## Offline analysis

```bash
arachnid-core parse-pcap capture.pcap -o ./ev-pcap
```

Reads a PCAP or PCAPNG **read-only**. The file stays where it is; it is not
copied into the container. Its SHA-256 is recorded in the custody log, binding
the analysis to the exact bytes analysed:

```
source pcap capture.pcap sha256=ce51b95b…7f6e02 size=454
```

Output goes to `artifacts/pcap_analysis.json`:

```json
{
  "schema_version": "1.0.0",
  "source": "sample.pcap",
  "source_sha256": "ce51b95bad82ae3fa035ff637cd43145df75a9fd2ce82037a6e0d4754a7f6e02",
  "datalink": "Linktype(1)",
  "packets": 3,
  "bytes": 382,
  "decode_errors": 0,
  "first_packet_utc": "2026-01-01T00:00:00Z",
  "last_packet_utc": "2026-01-01T00:00:02Z",
  "flows": [ … ],
  "indicators": [ … ]
}
```

### Decode errors

`decode_errors` counts frames the decoder could not parse: malformed, truncated
by snaplen, or a link type this build does not handle. Non-zero sets **exit code
4** and is reported.

**Non-IP frames are not errors.** ARP, LLDP and friends are counted in `packets`
and `bytes` but contribute no flow and no error — they simply are not flows.

---

## Link types

The link-layer header is stripped before decoding. A link type this build does
not decode returns nothing, so the frame is counted as a **decode error rather
than misparsed into a phantom flow**.

| Linktype | Name | Handling |
|---|---|---|
| `1` | Ethernet | header parsed by `etherparse` |
| `12`, `14`, `101` | Raw IP | no link header |
| `113` | Linux cooked capture v1 (the `any` device) | 16-byte header |
| `276` | Linux cooked capture v2 | 20-byte header |
| `0` | BSD loopback | 4-byte address family |
| anything else | | decode error |

For raw-IP link types there is no Ethernet header, so the first nibble is
version-sniffed (4 or 6) to decide how to slice the packet.

Capturing on the Linux `any` pseudo-device gives you linktype 113, which is
supported — useful when you do not know which interface the traffic will use.

---

## Flows

One transport-layer conversation, keyed by the 5-tuple **as first observed**:

```json
{
  "protocol": "tcp",
  "src_addr": "192.168.1.50",
  "src_port": 44102,
  "dst_addr": "93.184.216.34",
  "dst_port": 80,
  "packets": 1,
  "bytes": 159,
  "first_seen_utc": "2026-01-01T00:00:02Z",
  "last_seen_utc": "2026-01-01T00:00:02Z",
  "reassembled_bytes": 105,
  "truncated": false
}
```

- Keyed **directionally**: A→B and B→A are separate flows. That is deliberate —
  reassembly is per-direction, and so are the indicators drawn from it.
- `bytes` counts captured bytes (`caplen`), so a low `--snaplen` shows up here.
- `reassembled_bytes` is payload recovered by reassembly. TCP only; zero for UDP.
- `truncated` means the flow hit the reassembly ceiling.
- Sorted by bytes descending, then source address.

---

## TCP reassembly

Segments arrive out of order and get retransmitted, so payload is keyed by
**sequence offset in a `BTreeMap`** rather than appended in arrival order. That:

- sorts the stream correctly regardless of arrival order,
- collapses duplicate retransmissions,
- makes a gap **visible** instead of silently splicing two non-adjacent regions
  together.

### Signed offsets

Offsets are *signed* deltas from the first sequence number seen. The first
segment captured is not necessarily the lowest one — a reordered network, or a
capture that starts mid-stream, both break that assumption. A segment preceding
the base gets a negative offset and still sorts into place.

Signed 32-bit arithmetic is also what makes **sequence wraparound a non-event**,
on the standard TCP assumption that a live window spans well under 2 GiB.

### Retransmissions

A retransmission of an already-stored offset is dropped, **unless it carries
more data** than what is already held — in which case it replaces it. That
handles the overlapping-segment case without letting a later segment silently
rewrite earlier bytes.

### The ceiling

```
--max-stream-bytes <BYTES>    default 8388608 (8 MiB)
```

A capture holding a multi-gigabyte download must not put that download in RAM.
When a flow hits the ceiling:

- storage stops,
- `truncated` is set to `true` on that flow,
- the flow is **never silently shortened** — the flag is the contract.

Indicators live in the first few KiB of a stream, so a lower ceiling rarely
costs you one. Raise it when you need more of a payload reconstructed; lower it
when memory is tight:

```bash
arachnid-core parse-pcap big.pcap -o ./ev --max-stream-bytes 2097152

# how many flows were cut short?
jq '[.flows[] | select(.truncated)] | length' ./ev/artifacts/pcap_analysis.json
```

---

## Indicators

Everything here is derived from bytes that were **actually captured**.

> Nothing is resolved, enriched, or looked up against any remote service. A
> triage tool that phones out about the indicators it found leaks the
> investigation.

Indicators are deduplicated by `(kind, value)` and carry a count and a
first/last-seen window:

```json
{
  "kind": "http_host",
  "value": "c2.example.net",
  "count": 1,
  "first_seen_utc": "2026-01-01T00:00:02Z",
  "last_seen_utc": "2026-01-01T00:00:02Z",
  "context": "192.168.1.50:44102 -> 93.184.216.34:80"
}
```

Sorted by kind, then count descending, then value.

### The kinds

| Kind | Source | Notes |
|---|---|---|
| `ipv4` / `ipv6` | every decoded packet's source and destination | no context; these are the volume indicators |
| `dns_query` | UDP/53 and UDP/5353 (mDNS), and TCP/53 | the queried name |
| `dns_answer` | the same messages' answer section | rendered `name -> value`. A/AAAA records give the IP; CNAME gives the target |
| `tls_sni` | TLS ClientHello at the start of a reassembled TCP stream | plaintext handshake only |
| `http_uri` | cleartext HTTP request lines | the request target |
| `http_host` | `Host:` header | |
| `http_user_agent` | `User-Agent:` header | |

### DNS parsing

Names are decoded with **compression pointers followed**, and the walk is
bounded (128 steps) because a malicious or corrupt message can point in a cycle.
Question and answer sections are each capped at 64 entries.

DNS over TCP is length-prefixed; the parser skips the two-byte length before
reading the message.

Answer types decoded: **A** (type 1), **AAAA** (type 28), **CNAME** (type 5).
Others are skipped rather than guessed at.

### TLS SNI

Reassembly runs **first**, so a ClientHello split across segments still parses.
The parser walks: TLS record header → handshake header → version → random →
session id → cipher suites → compression methods → extensions, then finds
extension type `0x0000` (`server_name`) and reads the first name.

**Encrypted ClientHello yields no SNI**, and neither does a TLS 1.3 handshake
that omits it. Arachnid reads the plaintext handshake and **does not attempt to
decrypt anything**. That is a limitation, not a bug: a triage tool that
decrypted traffic would need keys it has no business holding.

### HTTP parsing

Deliberately **line-based rather than a full HTTP parser**. A reassembled stream
can hold several pipelined requests and a truncated tail; a strict parser would
reject the whole thing.

- Methods recognised: `GET`, `POST`, `PUT`, `HEAD`, `DELETE`, `OPTIONS`,
  `PATCH`, `TRACE`, `CONNECT`.
- A request line must also contain `HTTP/1.` to count, which keeps a payload
  that merely starts with `GET ` from being read as a request.
- Only `Host:` and `User-Agent:` headers are extracted — the two worth pivoting
  on.
- The scan is bounded to the **first 64 KiB** of a stream. Indicators live in
  the headers, not in an 8 MiB body.
- Header names are matched case-insensitively.

**HTTP/2 and HTTP/3 are not parsed.** Both are binary and usually inside TLS;
you get the `tls_sni` instead.

### Pivoting on indicators

```bash
# every hostname seen, whatever the source
jq -r '.indicators[]
       | select(.kind | test("dns_query|tls_sni|http_host"))
       | .value' ev-pcap/artifacts/pcap_analysis.json | sort -u

# the top talkers
jq -r '.indicators[] | select(.kind=="ipv4") | "\(.count)\t\(.value)"' \
   ev-pcap/artifacts/pcap_analysis.json | sort -rn | head -20

# DNS answers, resolved names to addresses
jq -r '.indicators[] | select(.kind=="dns_answer") | .value' \
   ev-pcap/artifacts/pcap_analysis.json
```

---

## Windows and Npcap

`wpcap.dll` is the user-mode half of the Npcap kernel driver, and it cannot be
statically linked by anyone. Arachnid handles this carefully:

**Delay-loading.** The `pcap` crate declares `wpcap.dll` as a normal import,
which means the process could not even *start* without Npcap — so `verify`,
`report` and `collect` would all fail with `STATUS_DLL_NOT_FOUND` on a host with
no packet driver, which describes most analyst workstations. The release build
passes `/DELAYLOAD:wpcap.dll`, deferring resolution to the first pcap call.

**Search path.** Npcap installs to `%SystemRoot%\System32\Npcap`, which is
deliberately *not* on the default DLL search path. Arachnid prepends it to
`PATH` once, before any capture thread exists.

**A readable error instead of an abort.** Calling into pcap without the DLL
would abort the process through the delay-load handler, which is not a Rust
error anyone can catch. So every entry point that touches pcap calls
`ensure_pcap_available()` first:

```
error: Npcap is not installed, or wpcap.dll is not on the DLL search path.
       Packet capture and PCAP parsing need it; install Npcap from https://npcap.com/.
       Every other subcommand (collect, verify, report) runs without it.
```

CI deliberately installs only the Npcap **SDK** and not the runtime, so the
no-Npcap path is tested on every push.

On Unix, libpcap is an ordinary shared-library dependency resolved at load time,
so there is nothing to check and `ensure_pcap_available()` is a no-op.

---

## Limitations

| Limitation | Detail |
|---|---|
| **Encrypted ClientHello** | no SNI. Nothing is decrypted, ever |
| **HTTP/2, HTTP/3, QUIC** | not parsed. You get IPs and TLS SNI |
| **TCP window under 2 GiB assumed** | the standard TCP assumption; what makes signed-offset arithmetic correct across wraparound |
| **Per-flow reassembly is capped** | 8 MiB by default. A flow that hits it is flagged `truncated` |
| **HTTP scan is capped** | first 64 KiB of a stream |
| **Unsupported link types** | counted as decode errors rather than misparsed |
| **No IP fragment reassembly** | fragmented datagrams decode from the first fragment only |
| **Live capture shows counters only** | flow detail comes from re-reading the sealed savefile |
| **Capture is receive-only** | no injection, no interception, no transmission of any kind |

---

[← Collectors](06-Collectors.md) · [Home](Home.md) · [Next: Reports & Schemas →](08-Reports-and-Schemas.md)
