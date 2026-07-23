//! Report generation.
//!
//! The JSON report is the contract: schema-versioned, documented in
//! `schema/report.schema.json`, and consumed downstream by the Arachnid Recover
//! module. The Markdown and HTML renderings are for a human skimming the run and
//! carry no information the JSON lacks.

use std::fmt::Write as _;

use anyhow::Result;
use arachnid_collect::{Collection, MemoryAcquisition};
use arachnid_evidence::Manifest;
use arachnid_netcap::{CaptureStats, PcapAnalysis};
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to [`Report`]. Consumers must reject a
/// major version they do not know.
pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub manifest: Manifest,
    /// Present for a `collect` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<Collection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryAcquisition>,
    /// Present for a `capture` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureStats>,
    /// Present for a `parse-pcap` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap: Option<PcapAnalysis>,
    /// `name` -> SHA-256, mirroring the custody log for quick reference. The
    /// custody log remains the authority; this is a convenience view.
    pub artifacts: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub name: String,
    pub sha256: String,
}

impl Report {
    pub fn new(manifest: Manifest) -> Self {
        Report {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            manifest,
            collection: None,
            memory: None,
            capture: None,
            pcap: None,
            artifacts: Vec::new(),
        }
    }

    pub fn artifact(&mut self, name: &str, sha256: String) {
        if !sha256.is_empty() {
            self.artifacts.push(ArtifactRef {
                name: name.into(),
                sha256,
            });
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}

/// Top-N cutoff for the human summary. The JSON always holds everything; this
/// only governs what fits on a screen.
const TOP_N: usize = 20;

pub fn to_markdown(r: &Report) -> String {
    let m = &r.manifest;
    let mut s = String::new();

    let _ = writeln!(s, "# Arachnid Forensic — Core Triage Report\n");
    let _ = writeln!(s, "| | |");
    let _ = writeln!(s, "|---|---|");
    let _ = writeln!(s, "| Container | `{}` |", m.container_id);
    let _ = writeln!(s, "| Collected | {} |", m.created_utc);
    let _ = writeln!(s, "| Host | {} ({}) |", m.host, m.platform);
    let _ = writeln!(s, "| Operator | {} |", m.operator);
    let _ = writeln!(s, "| Tool | {} {} |", m.tool, m.tool_version);
    let _ = writeln!(s, "| Signing key | `{}` |", m.public_key);
    let _ = writeln!(s, "| Report schema | {} |\n", r.schema_version);

    if let Some(c) = &r.collection {
        if !c.warnings.is_empty() {
            let _ = writeln!(s, "## ⚠ Collection gaps\n");
            let _ = writeln!(s, "These collectors did not complete. Absence below is not evidence of absence on the host.\n");
            for w in &c.warnings {
                let _ = writeln!(s, "- {w}");
            }
            let _ = writeln!(s);
        }

        let _ = writeln!(s, "## Summary\n");
        let _ = writeln!(s, "- Processes: **{}**", c.processes.len());
        let _ = writeln!(s, "- Network connections: **{}**", c.connections.len());
        let listening = c.connections.iter().filter(|x| x.state == "LISTEN").count();
        let _ = writeln!(s, "- Listening sockets: **{listening}**");
        let external = c
            .connections
            .iter()
            .filter(|x| x.remote_addr.as_deref().is_some_and(is_routable))
            .count();
        let _ = writeln!(s, "- Connections to routable addresses: **{external}**");
        let _ = writeln!(s, "- Active sessions: **{}**", c.sessions.len());
        let _ = writeln!(s, "- Kernel modules: **{}**", c.kernel_modules.len());
        let _ = writeln!(s, "- Persistence entries: **{}**\n", c.persistence.len());

        if !c.sessions.is_empty() {
            let _ = writeln!(s, "## Active sessions\n");
            let _ = writeln!(s, "| User | Terminal | Remote host | Login |");
            let _ = writeln!(s, "|---|---|---|---|");
            for x in &c.sessions {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    x.user,
                    x.terminal.as_deref().unwrap_or("-"),
                    x.remote_host.as_deref().unwrap_or("-"),
                    x.login_time.as_deref().unwrap_or("-")
                );
            }
            let _ = writeln!(s);
        }

        // External connections first: that is where triage actually starts.
        let mut conns: Vec<_> = c
            .connections
            .iter()
            .filter(|x| x.remote_addr.as_deref().is_some_and(is_routable))
            .collect();
        if !conns.is_empty() {
            conns.sort_by_key(|x| x.remote_addr.clone());
            let _ = writeln!(s, "## Connections to routable addresses\n");
            let _ = writeln!(s, "| Proto | Local | Remote | State | PID | Process |");
            let _ = writeln!(s, "|---|---|---|---|---|---|");
            for x in conns.iter().take(TOP_N) {
                let _ = writeln!(
                    s,
                    "| {} | {}:{} | {}:{} | {} | {} | {} |",
                    x.protocol,
                    x.local_addr,
                    x.local_port,
                    x.remote_addr.as_deref().unwrap_or("-"),
                    x.remote_port.unwrap_or(0),
                    x.state,
                    x.pids
                        .first()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into()),
                    x.process_name.as_deref().unwrap_or("-")
                );
            }
            if conns.len() > TOP_N {
                let _ = writeln!(s, "\n_{} more in the JSON report._", conns.len() - TOP_N);
            }
            let _ = writeln!(s);
        }

        if !c.persistence.is_empty() {
            let _ = writeln!(s, "## Persistence entries\n");
            let _ = writeln!(s, "| Kind | Location | Name | Value |");
            let _ = writeln!(s, "|---|---|---|---|");
            for x in c.persistence.iter().take(TOP_N) {
                let _ = writeln!(
                    s,
                    "| {} | `{}` | {} | {} |",
                    x.kind,
                    x.location,
                    x.name,
                    truncate(x.value.as_deref().unwrap_or("-"), 60)
                );
            }
            if c.persistence.len() > TOP_N {
                let _ = writeln!(
                    s,
                    "\n_{} more in the JSON report._",
                    c.persistence.len() - TOP_N
                );
            }
            let _ = writeln!(s);
        }

        // Processes without a resolvable on-disk image: deleted binaries, kernel
        // threads, and anything running from memory. Worth an analyst's eye.
        let unresolved: Vec<_> = c
            .processes
            .iter()
            .filter(|p| p.exe.is_some() && p.exe_sha256.is_none())
            .collect();
        if !unresolved.is_empty() {
            let _ = writeln!(s, "## Processes with an unhashable image\n");
            let _ = writeln!(s, "A missing hash means the path did not resolve to a readable file: a deleted or replaced binary, or insufficient privilege.\n");
            let _ = writeln!(s, "| PID | Name | Path |");
            let _ = writeln!(s, "|---|---|---|");
            for p in unresolved.iter().take(TOP_N) {
                let _ = writeln!(
                    s,
                    "| {} | {} | `{}` |",
                    p.pid,
                    p.name,
                    p.exe.as_deref().unwrap_or("-")
                );
            }
            let _ = writeln!(s);
        }
    }

    if let Some(mem) = &r.memory {
        let _ = writeln!(s, "## Memory acquisition\n");
        let _ = writeln!(s, "- Tool: `{}`", mem.tool);
        let _ = writeln!(
            s,
            "- Tool SHA-256: `{}` (verified before execution)",
            mem.tool_sha256
        );
        let _ = writeln!(s, "- Image: `{}`", mem.output_artifact);
        let _ = writeln!(s, "- Window: {} → {}\n", mem.started_utc, mem.finished_utc);
    }

    if let Some(cap) = &r.capture {
        let _ = writeln!(s, "## Live capture\n");
        let _ = writeln!(s, "- Device: `{}` ({})", cap.device, cap.datalink);
        let _ = writeln!(s, "- Filter: `{}`", cap.filter.as_deref().unwrap_or("none"));
        let _ = writeln!(s, "- Promiscuous: {}", cap.promiscuous);
        let _ = writeln!(
            s,
            "- Packets: **{}** ({} bytes)",
            cap.packets_written, cap.bytes_written
        );
        let _ = writeln!(s, "- Window: {} → {}", cap.started_utc, cap.finished_utc);
        let _ = writeln!(s, "- Stopped: {}", cap.stop_reason);
        if cap.packets_dropped_kernel > 0 || cap.packets_dropped_interface > 0 {
            let _ = writeln!(
                s,
                "- ⚠ **Dropped {} (kernel) / {} (interface) — this capture has gaps.**",
                cap.packets_dropped_kernel, cap.packets_dropped_interface
            );
        }
        let _ = writeln!(s);
    }

    if let Some(p) = &r.pcap {
        let _ = writeln!(s, "## PCAP analysis\n");
        let _ = writeln!(s, "- Source: `{}`", p.source);
        if let Some(h) = &p.source_sha256 {
            let _ = writeln!(s, "- Source SHA-256: `{h}`");
        }
        let _ = writeln!(
            s,
            "- Packets: **{}** ({} bytes), {} flows",
            p.packets,
            p.bytes,
            p.flows.len()
        );
        if p.decode_errors > 0 {
            let _ = writeln!(s, "- ⚠ {} frames could not be decoded", p.decode_errors);
        }
        let _ = writeln!(
            s,
            "- Window: {} → {}\n",
            p.first_packet_utc.as_deref().unwrap_or("-"),
            p.last_packet_utc.as_deref().unwrap_or("-")
        );

        let named: Vec<_> = p
            .indicators
            .iter()
            .filter(|i| i.kind != "ipv4" && i.kind != "ipv6")
            .collect();
        if !named.is_empty() {
            let _ = writeln!(s, "### Indicators\n");
            let _ = writeln!(s, "| Kind | Value | Count |");
            let _ = writeln!(s, "|---|---|---|");
            for i in named.iter().take(TOP_N * 2) {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} |",
                    i.kind,
                    truncate(&i.value, 70),
                    i.count
                );
            }
            let _ = writeln!(s);
        }

        if !p.flows.is_empty() {
            let _ = writeln!(s, "### Top flows by volume\n");
            let _ = writeln!(s, "| Proto | Source | Destination | Packets | Bytes |");
            let _ = writeln!(s, "|---|---|---|---|---|");
            for f in p.flows.iter().take(TOP_N) {
                let _ = writeln!(
                    s,
                    "| {} | {}:{} | {}:{} | {} | {} |",
                    f.protocol, f.src_addr, f.src_port, f.dst_addr, f.dst_port, f.packets, f.bytes
                );
            }
            let _ = writeln!(s);
        }
    }

    if !r.artifacts.is_empty() {
        let _ = writeln!(s, "## Artifacts\n");
        let _ = writeln!(s, "Verify with `arachnid-core verify <container>`.\n");
        let _ = writeln!(s, "| Artifact | SHA-256 |");
        let _ = writeln!(s, "|---|---|");
        for a in &r.artifacts {
            let _ = writeln!(s, "| `{}` | `{}` |", a.name, a.sha256);
        }
    }
    s
}

/// Wrap the Markdown summary in a self-contained HTML page. No external assets:
/// an evidence report must render on an air-gapped analysis workstation.
pub fn to_html(r: &Report) -> String {
    let md = to_markdown(r);
    let mut body = String::new();
    let mut in_table = false;

    let flush_table = |body: &mut String, in_table: &mut bool| {
        if *in_table {
            body.push_str("</table>\n");
            *in_table = false;
        }
    };

    for line in md.lines() {
        let t = line.trim();
        if t.starts_with("|---") {
            continue; // Markdown alignment row; HTML needs no equivalent.
        }
        if let Some(row) = t.strip_prefix('|').and_then(|x| x.strip_suffix('|')) {
            if !in_table {
                body.push_str("<table>\n");
                in_table = true;
            }
            body.push_str("<tr>");
            for cell in row.split('|') {
                body.push_str(&format!("<td>{}</td>", inline(cell.trim())));
            }
            body.push_str("</tr>\n");
            continue;
        }
        flush_table(&mut body, &mut in_table);
        if let Some(h) = t.strip_prefix("### ") {
            body.push_str(&format!("<h3>{}</h3>\n", esc(h)));
        } else if let Some(h) = t.strip_prefix("## ") {
            body.push_str(&format!("<h2>{}</h2>\n", esc(h)));
        } else if let Some(h) = t.strip_prefix("# ") {
            body.push_str(&format!("<h1>{}</h1>\n", esc(h)));
        } else if let Some(li) = t.strip_prefix("- ") {
            body.push_str(&format!("<p class=\"li\">• {}</p>\n", inline(li)));
        } else if !t.is_empty() {
            body.push_str(&format!("<p>{}</p>\n", inline(t)));
        }
    }
    flush_table(&mut body, &mut in_table);

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arachnid Forensic — {}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
       max-width: 62rem; margin: 2rem auto; padding: 0 1.25rem; }}
h1 {{ font-size: 1.6rem; border-bottom: 2px solid currentColor; padding-bottom: .4rem; }}
h2 {{ font-size: 1.2rem; margin-top: 2rem; }}
h3 {{ font-size: 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin: .75rem 0; font-size: .88rem;
        display: block; overflow-x: auto; }}
td {{ border: 1px solid rgba(128,128,128,.4); padding: .3rem .55rem; text-align: left;
     vertical-align: top; }}
tr:first-child td {{ font-weight: 600; background: rgba(128,128,128,.12); }}
code {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .85em;
       background: rgba(128,128,128,.15); padding: .1em .35em; border-radius: 3px;
       word-break: break-all; }}
.li {{ margin: .2rem 0; }}
</style></head><body>
{}
</body></html>
"#,
        esc(&r.manifest.container_id),
        body
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape, then re-apply the two inline markers the summary actually uses.
fn inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let escaped = esc(s);
    let mut rest = escaped.as_str();

    while let Some(i) = rest.find('`') {
        out.push_str(&rest[..i]);
        match rest[i + 1..].find('`') {
            Some(j) => {
                out.push_str(&format!("<code>{}</code>", &rest[i + 1..i + 1 + j]));
                rest = &rest[i + j + 2..];
            }
            None => {
                rest = &rest[i..];
                break;
            }
        }
    }
    out.push_str(rest);

    // Bold is only ever used around a whole number in this summary.
    while let Some(i) = out.find("**") {
        let Some(j) = out[i + 2..].find("**") else {
            break;
        };
        let inner = out[i + 2..i + 2 + j].to_string();
        out.replace_range(i..i + j + 4, &format!("<strong>{inner}</strong>"));
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.replace('|', "\\|");
    }
    let cut: String = s.chars().take(n).collect();
    format!("{}…", cut.replace('|', "\\|"))
}

/// Excludes loopback, link-local, private, multicast, and unspecified addresses:
/// what remains is traffic that actually left the network.
fn is_routable(addr: &str) -> bool {
    use std::net::IpAddr;
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT: not routable on the public internet.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        Ok(IpAddr::V6(v6)) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fe80::/10 link-local and fc00::/7 unique-local.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00)
        }
        Err(_) => false,
    }
}
