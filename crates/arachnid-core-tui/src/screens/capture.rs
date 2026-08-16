//! Capture: live packet capture into an evidence container.
//!
//! The capture thread outlives this screen, so the operator can watch a
//! collection or read a report while it runs. Stopping sets a flag rather than
//! killing the thread: the savefile is flushed and its digest reaches the
//! custody log, and a capture lost to an abrupt exit is evidence lost.
//!
//! While capture runs the only live figures are the counters
//! `arachnid_netcap::Progress` publishes. Decoding packets to fill a table would
//! put per-frame work in the capture loop, which is how a capture falls behind
//! the link and drops evidence — so the flow and protocol breakdown come from a
//! read-only `parse_pcap` of the finished savefile instead.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arachnid_evidence::Container;
use arachnid_netcap as netcap;
use arachnid_report::{seal_into, Report};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Action, App, Input, Msg, Running, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "field"),
    ("h/l", "device"),
    ("Enter", "edit / toggle"),
    ("s", "start / stop"),
];

/// device, output, filter, operator, signing key, promiscuous.
const FIELDS: usize = 6;

/// Rows of recent flows shown after a capture. The full set is in the analysis;
/// this is what fits.
const FLOW_ROWS: usize = 12;

pub struct State {
    pub devices: Vec<netcap::DeviceInfo>,
    pub device: usize,
    pub output: Input,
    pub filter: Input,
    pub operator: Input,
    pub signing_key: Input,
    pub promiscuous: bool,
    pub focus: usize,
    pub last: Option<Done>,
}

pub struct Done {
    pub stats: netcap::CaptureStats,
    pub root: PathBuf,
    pub pcap: PathBuf,
    pub fingerprint: String,
    /// Read-only analysis of the savefile just written. Display only — nothing
    /// from it is added to the container, because `arachnid-core capture` does
    /// not add it either.
    pub analysis: Option<netcap::PcapAnalysis>,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            devices: Vec::new(),
            device: 0,
            output: Input::default(),
            filter: Input::default(),
            operator: Input::new(saved.operator.clone()),
            signing_key: Input::default(),
            promiscuous: false,
            focus: 0,
            last: None,
        }
    }

    /// Devices come from the startup probe rather than being re-enumerated here;
    /// `list_devices` is the same call either way.
    pub fn adopt_devices(&mut self, devices: &[netcap::DeviceInfo]) {
        self.devices = devices.to_vec();
    }

    fn device_name(&self) -> Option<&str> {
        self.devices.get(self.device).map(|d| d.name.as_str())
    }
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        let s = &mut app.capture_ui;
        return match s.focus {
            1 => s.output.key(&key),
            2 => s.filter.key(&key),
            3 => s.operator.key(&key),
            4 => s.signing_key.key(&key),
            _ => false,
        };
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::wrap(&mut app.capture_ui.focus, 1, FIELDS),
        KeyCode::Char('k') | KeyCode::Up => super::wrap(&mut app.capture_ui.focus, -1, FIELDS),
        KeyCode::Char('l') | KeyCode::Right => {
            let n = app.capture_ui.devices.len();
            super::step(&mut app.capture_ui.device, 1, n);
        }
        KeyCode::Char('h') | KeyCode::Left => {
            let n = app.capture_ui.devices.len();
            super::step(&mut app.capture_ui.device, -1, n);
        }
        KeyCode::Enter => match app.capture_ui.focus {
            0 => {}
            5 => app.capture_ui.promiscuous = !app.capture_ui.promiscuous,
            _ => app.editing = true,
        },
        KeyCode::Char('s') => toggle(app),
        _ => return false,
    }
    true
}

fn toggle(app: &mut App) {
    if app.capture.is_some() {
        app.ask(
            "Stop the running capture? The savefile is flushed and sealed.",
            Action::StopCapture,
        );
        return;
    }
    let Some(device) = app.capture_ui.device_name().map(str::to_string) else {
        app.toast(
            "no capture device available (needs root/CAP_NET_RAW on Linux, Npcap on Windows)",
            true,
        );
        return;
    };
    let out = app.capture_ui.output.trimmed().to_string();
    if out.is_empty() {
        app.toast("output directory is required", true);
        return;
    }
    app.ask(
        format!("Capture on {device} into a new container at {out}?"),
        Action::StartCapture,
    );
}

pub fn start(app: &mut App) {
    let s = &app.capture_ui;
    let Some(device) = s.device_name().map(str::to_string) else {
        return;
    };
    let out = PathBuf::from(s.output.trimmed());
    let filter = match s.filter.trimmed() {
        "" => None,
        f => Some(f.to_string()),
    };
    let operator = match s.operator.trimmed() {
        "" => crate::app::default_operator(),
        o => o.to_string(),
    };
    let signing_key = match s.signing_key.trimmed() {
        "" => None,
        k => Some(PathBuf::from(k)),
    };
    let promiscuous = s.promiscuous;

    let stop = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(netcap::Progress::default());
    app.capture = Some(Running {
        stop: stop.clone(),
        progress: progress.clone(),
        started: Instant::now(),
        device: device.clone(),
        output: out.clone(),
    });
    app.capture_ui.last = None;

    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let opts = netcap::LiveOptions {
            device,
            filter,
            snaplen: 65535,
            promiscuous,
            max_packets: None,
            duration: None,
        };
        let r = run(
            &opts,
            &out,
            operator.as_str(),
            signing_key.as_deref(),
            &stop,
            &progress,
            &tx,
        )
        .map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::CaptureDone(Box::new(r)));
    });
}

pub fn stop(app: &mut App) {
    if let Some(c) = &app.capture {
        c.stop.store(true, Ordering::Relaxed);
        app.toast("stopping capture; flushing savefile", false);
    }
}

/// The same sequence `arachnid-core capture` performs, through the same library
/// calls, with one addition that writes nothing: the finished savefile is parsed
/// read-only so the screen can show what was captured.
#[allow(clippy::too_many_arguments)]
fn run(
    opts: &netcap::LiveOptions,
    out: &std::path::Path,
    operator: &str,
    signing_key: Option<&std::path::Path>,
    stop: &AtomicBool,
    progress: &netcap::Progress,
    tx: &std::sync::mpsc::Sender<Msg>,
) -> Result<Done> {
    let key = signing_key
        .map(arachnid_evidence::load_signing_key)
        .transpose()?;
    let mut container = Container::create(out, operator, key, false)?;
    container.note(format!(
        "invocation: arachnid-tui capture --output {} --device {}{}{}",
        out.display(),
        opts.device,
        opts.filter
            .as_ref()
            .map(|f| format!(" --filter {f:?}"))
            .unwrap_or_default(),
        if opts.promiscuous {
            " --promiscuous"
        } else {
            ""
        }
    ))?;
    let mut report = Report::new(container.manifest().clone());

    let pcap = container.artifact_path("capture.pcap");
    std::fs::create_dir_all(pcap.parent().expect("artifact paths have a parent"))?;
    tracing::info!(device = %opts.device, filter = ?opts.filter, "starting capture");

    let stats = netcap::capture_live_with_progress(opts, &pcap, stop, progress)?;
    tracing::info!(
        packets = stats.packets_written,
        dropped = stats.packets_dropped_kernel,
        reason = stats.stop_reason,
        "capture finished"
    );

    report.artifact("capture.pcap", container.seal("capture.pcap")?);
    if stats.packets_dropped_kernel > 0 || stats.packets_dropped_interface > 0 {
        container.note(format!(
            "capture dropped {} kernel / {} interface packets; evidence has gaps",
            stats.packets_dropped_kernel, stats.packets_dropped_interface
        ))?;
    }
    report.capture = Some(stats.clone());

    seal_into(&mut container, &report).context("seal report into container")?;
    let fingerprint = container.key_fingerprint();
    let root = container.root().to_path_buf();
    container.finish()?;

    // The container is complete and sealed before this runs, so a parse failure
    // costs a display, never evidence.
    let _ = tx.send(Msg::Toast(
        "capture sealed; analysing savefile".into(),
        false,
    ));
    let analysis = netcap::parse_pcap(&pcap, &netcap::ParseOptions::default())
        .map_err(|e| tracing::warn!(error = %format!("{e:#}"), "post-capture analysis failed"))
        .ok();

    Ok(Done {
        stats,
        root,
        pcap,
        fingerprint,
        analysis,
    })
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            app.remember_container(&done.root);
            app.remember_pcap(&done.pcap);
            app.toast(
                format!(
                    "captured {} packets ({}) — {}",
                    done.stats.packets_written,
                    bytes(done.stats.bytes_written),
                    done.stats.stop_reason
                ),
                false,
            );
            app.capture_ui.last = Some(done);
        }
        Err(e) => app.toast(e, true),
    }
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let [form, live, results] = Layout::vertical([
        Constraint::Length(FIELDS as u16 + 1),
        Constraint::Length(4),
        Constraint::Min(3),
    ])
    .areas(area);

    form_rows(frame, form, app);
    live_rows(frame, live, app);
    result_rows(frame, results, app);
}

fn form_rows(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.capture_ui;
    let rows: [Rect; 7] = Layout::vertical([Constraint::Length(1); 7]).areas(area);
    let device = match s.devices.get(s.device) {
        Some(d) => format!(
            "{}  ({}/{}){}",
            d.name,
            s.device + 1,
            s.devices.len(),
            if d.loopback { "  [loopback]" } else { "" }
        ),
        None => "none available".into(),
    };
    ui::field(frame, rows[0], "device  h/l", &device, s.focus == 0, false);
    ui::field(
        frame,
        rows[1],
        "output dir",
        &s.output.value,
        s.focus == 1,
        app.editing && s.focus == 1,
    );
    ui::field(
        frame,
        rows[2],
        "BPF filter",
        &s.filter.value,
        s.focus == 2,
        app.editing && s.focus == 2,
    );
    ui::field(
        frame,
        rows[3],
        "operator",
        &s.operator.value,
        s.focus == 3,
        app.editing && s.focus == 3,
    );
    ui::field(
        frame,
        rows[4],
        "signing key",
        &s.signing_key.value,
        s.focus == 4,
        app.editing && s.focus == 4,
    );
    ui::field(
        frame,
        rows[5],
        "promiscuous",
        if s.promiscuous { "yes" } else { "no" },
        s.focus == 5,
        false,
    );
    frame.render_widget(
        Paragraph::new(Line::from(ui::dim(if s.promiscuous {
            "  promiscuous mode changes the interface's receive mode — an observable change"
        } else {
            "  capturing only frames addressed to this host"
        }))),
        rows[6],
    );
}

fn live_rows(frame: &mut Frame, area: Rect, app: &App) {
    let t = Theme::get();
    let Some(c) = &app.capture else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(" not capturing — press s to start"))),
            area,
        );
        return;
    };

    let packets = c.progress.packets.load(Ordering::Relaxed);
    let written = c.progress.bytes.load(Ordering::Relaxed);
    let elapsed = c.started.elapsed();
    let rate = packets as f64 / elapsed.as_secs_f64().max(0.001);
    let lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} capturing ", app.spinner()), t.selected()),
            Span::raw(format!("on {} → {}", c.device, c.output.display())),
        ]),
        Line::from(vec![
            ui::dim(" packets     "),
            Span::raw(format!("{packets}")),
            ui::dim("    bytes "),
            Span::raw(bytes(written)),
            ui::dim("    rate "),
            Span::raw(format!("{rate:.0}/s")),
            ui::dim("    elapsed "),
            Span::raw(hms(elapsed)),
        ]),
        Line::from(ui::dim(
            " drop counts and the flow breakdown come from the driver and the savefile when the capture stops",
        )),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}
