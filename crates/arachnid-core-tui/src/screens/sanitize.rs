//! Sanitize: standards-compliant secure erasure.
//!
//! Every other screen in this TUI is read-only against the target. This one
//! destroys data, so it is deliberately the least convenient screen here.
//!
//! The flow is a one-way sequence of sub-views — devices, method, confirm,
//! progress, result — and each step forward costs a deliberate action. There is
//! no path from a list selection to a running wipe in one keypress, no way to
//! select more than one device, and the confirm view is drawn to look nothing
//! like the ordinary `y/n` confirmation used everywhere else in the app, so an
//! operator cannot clear it on muscle memory.
//!
//! The rails themselves are not implemented here. `arachnid_sanitize_core`
//! owns them, and this screen cannot bypass them: it has to obtain a
//! `Clearance` from `safety::authorize` just as the CLI does, and the engine
//! accepts nothing else. What this module adds is making the state of those
//! rails visible before the operator commits.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arachnid_sanitize_core::{
    cert, device, engine,
    pattern::WipeMethod,
    safety::{self, WipeRequest},
    target::RawDeviceTarget,
    verify, Device,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Msg, SanitizeJob, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "select"),
    ("Enter", "next step"),
    ("Esc", "back a step"),
    ("r", "re-enumerate"),
    ("f", "allow system disk"),
    ("d", "dry run"),
    ("x", "cancel job"),
];

/// The methods offered, in the order they appear.
const METHODS: [WipeMethod; 5] = [
    WipeMethod::NistClear,
    WipeMethod::NistPurge,
    WipeMethod::Dod3Pass,
    WipeMethod::Dod7Pass,
    WipeMethod::CryptoErase,
];

/// Editable fields on the confirm view.
const CONFIRM_FIELDS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Devices,
    Method,
    Confirm,
    Progress,
    Result,
}

pub struct State {
    pub view: View,
    pub devices: Vec<Device>,
    pub sel: usize,
    pub method: usize,
    /// The operator's typed copy of the device serial.
    pub serial: crate::app::Input,
    pub cert_dir: crate::app::Input,
    /// Which confirm-view field has the keyboard.
    pub field: usize,
    /// Explicit acknowledgement that the chosen device hosts the running OS.
    pub force_system: bool,
    pub dry_run: bool,
    /// When the confirm view was entered, for the countdown gate.
    pub confirm_since: Option<Instant>,
    pub enumerating: bool,
    pub last: Option<Done>,
    /// The most recent refusal, shown in place rather than as a toast so it
    /// stays on screen while the operator fixes it.
    pub refusal: Option<String>,
}

pub struct Done {
    pub device: Device,
    pub outcome: engine::WipeOutcome,
    pub verification: verify::VerifyReport,
    /// `None` when the wipe or its verification did not earn one.
    pub certificate: Option<cert::Certificate>,
    pub refused: Option<String>,
    pub register: PathBuf,
    pub fingerprint: String,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            view: View::Devices,
            devices: Vec::new(),
            sel: 0,
            method: 0,
            serial: crate::app::Input::default(),
            cert_dir: crate::app::Input::new(
                saved
                    .last_container
                    .clone()
                    .unwrap_or_else(|| ".".to_string()),
            ),
            field: 0,
            force_system: false,
            dry_run: true,
            confirm_since: None,
            enumerating: false,
            last: None,
            refusal: None,
        }
    }

    pub fn selected(&self) -> Option<&Device> {
        self.devices.get(self.sel)
    }

    fn method(&self) -> WipeMethod {
        METHODS[self.method.min(METHODS.len() - 1)]
    }

    /// True once the confirm view has been on screen long enough for the final
    /// keypress to be accepted.
    pub fn cooldown_remaining(&self) -> Option<Duration> {
        let since = self.confirm_since?;
        safety::CONFIRM_COOLDOWN.checked_sub(since.elapsed())
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Re-read the attached devices. Runs on a thread: on Windows this opens every
/// physical drive in turn, which is slow enough to stutter the render loop.
pub fn enumerate(app: &mut App) {
    if app.sanitize.enumerating {
        return;
    }
    app.sanitize.enumerating = true;
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = device::enumerate().map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::SanitizeDevices(Box::new(r)));
    });
}

pub fn adopt_devices(app: &mut App, result: Result<Vec<Device>, String>) {
    app.sanitize.enumerating = false;
    match result {
        Ok(devices) => {
            if devices.is_empty() {
                app.toast(
                    "no storage devices visible — enumeration needs Administrator on Windows, root on Linux",
                    true,
                );
            }
            app.sanitize.sel = app.sanitize.sel.min(devices.len().saturating_sub(1));
            app.sanitize.devices = devices;
        }
        Err(e) => app.toast(e, true),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        let s = &mut app.sanitize;
        return match s.field {
            0 => s.serial.key(&key),
            _ => s.cert_dir.key(&key),
        };
    }

    match app.sanitize.view {
        View::Devices => devices_key(app, key),
        View::Method => method_key(app, key),
        View::Confirm => confirm_key(app, key),
        View::Progress => progress_key(app, key),
        View::Result => result_key(app, key),
    }
}

fn devices_key(app: &mut App, key: KeyEvent) -> bool {
    let n = app.sanitize.devices.len();
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.sanitize.sel, 1, n),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.sanitize.sel, -1, n),
        KeyCode::Char('r') => enumerate(app),
        KeyCode::Char('f') => {
            app.sanitize.force_system = !app.sanitize.force_system;
            if app.sanitize.force_system {
                app.toast(
                    "system-disk wipes are now permitted for this session — this will destroy the running OS",
                    true,
                );
            }
        }
        KeyCode::Enter => {
            let Some(d) = app.sanitize.selected().cloned() else {
                app.toast("no device selected", true);
                return true;
            };
            // The list itself refuses to hand a system disk to the wipe flow.
            // authorize() would refuse it again later; stopping here means the
            // operator never types a serial for a device they cannot wipe.
            if d.is_system && !app.sanitize.force_system {
                app.sanitize.refusal =
                    Some(format!(
                    "{} hosts the running operating system ({}). Press f to permit system-disk \
                     wipes if that is genuinely what you intend.",
                    d.path,
                    d.system_reason.as_deref().unwrap_or("mounted system volume")
                ));
                return true;
            }
            app.sanitize.refusal = None;
            app.sanitize.view = View::Method;
        }
        _ => return false,
    }
    true
}

fn method_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            super::step(&mut app.sanitize.method, 1, METHODS.len())
        }
        KeyCode::Char('k') | KeyCode::Up => {
            super::step(&mut app.sanitize.method, -1, METHODS.len())
        }
        KeyCode::Esc => app.sanitize.view = View::Devices,
        KeyCode::Enter => {
            app.sanitize.serial.set("");
            app.sanitize.field = 0;
            app.sanitize.confirm_since = Some(Instant::now());
            app.sanitize.refusal = None;
            app.sanitize.view = View::Confirm;
        }
        _ => return false,
    }
    true
}

fn confirm_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.sanitize.confirm_since = None;
            app.sanitize.view = View::Method;
        }
        KeyCode::Tab => super::wrap(&mut app.sanitize.field, 1, CONFIRM_FIELDS),
        KeyCode::Char('j') | KeyCode::Down => {
            super::wrap(&mut app.sanitize.field, 1, CONFIRM_FIELDS)
        }
        KeyCode::Char('k') | KeyCode::Up => {
            super::wrap(&mut app.sanitize.field, -1, CONFIRM_FIELDS)
        }
        KeyCode::Enter => app.editing = true,
        KeyCode::Char('d') => app.sanitize.dry_run = !app.sanitize.dry_run,
        // The commit key is deliberately not Enter, and deliberately not y:
        // both are what the ordinary confirm dialog takes, and this must not be
        // clearable by the reflex that clears those.
        KeyCode::Char('W') => start(app),
        _ => return false,
    }
    true
}

fn progress_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('x') => {
            if app.sanitize_job.is_some() {
                app.ask(
                    "Cancel the running wipe? The device will be left partially overwritten \
                     and will NOT be certified.",
                    crate::app::Action::CancelWipe,
                );
            }
        }
        KeyCode::Esc => app.sanitize.view = View::Devices,
        _ => return false,
    }
    true
}

fn result_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.sanitize.view = View::Devices,
        KeyCode::Char('e') => export(app),
        _ => return false,
    }
    true
}

/// Write the certificate beside the register in both readable formats.
fn export(app: &mut App) {
    let Some(done) = &app.sanitize.last else {
        return;
    };
    let Some(c) = &done.certificate else {
        app.toast(
            "no certificate to export — this wipe was not certified",
            true,
        );
        return;
    };
    let dir = done
        .register
        .parent()
        .unwrap_or(&done.register)
        .to_path_buf();
    let stem = format!("erasure-{}", c.certificate_id);
    let write = |ext: &str, body: String| -> Result<PathBuf> {
        let path = dir.join(format!("{stem}.{ext}"));
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    };
    match write("md", cert::to_markdown(c)).and_then(|_| write("html", cert::to_html(c))) {
        Ok(path) => app.toast(format!("certificate exported to {}", path.display()), false),
        Err(e) => app.toast(format!("{e:#}"), true),
    }
}

// ---------------------------------------------------------------------------
// Running the job
// ---------------------------------------------------------------------------

pub fn start(app: &mut App) {
    if app.sanitize_job.is_some() {
        app.toast("a wipe is already running", true);
        return;
    }
    // The countdown is a gate, not a decoration: the key is rejected until it
    // has elapsed.
    if let Some(left) = app.sanitize.cooldown_remaining() {
        app.toast(
            format!(
                "wait {:.0}s — read the summary above",
                left.as_secs_f64().ceil()
            ),
            true,
        );
        return;
    }
    let Some(selected) = app.sanitize.selected().cloned() else {
        return;
    };

    let request = WipeRequest {
        device: selected.clone(),
        method: app.sanitize.method(),
        typed_serial: app.sanitize.serial.trimmed().to_string(),
        force_system_volume: app.sanitize.force_system,
        dry_run: app.sanitize.dry_run,
        operator: app.saved.operator.clone(),
    };

    // Re-enumerate before authorizing. The device at this path may have been
    // swapped since the list was drawn, and that is exactly what the
    // re-enumeration rail exists to catch.
    let present = match device::enumerate() {
        Ok(devices) => devices.into_iter().find(|d| d.path == selected.path),
        Err(e) => {
            app.sanitize.refusal = Some(format!("could not re-enumerate devices: {e:#}"));
            return;
        }
    };

    let clearance = match safety::authorize(request, present.as_ref()) {
        Ok(c) => c,
        Err(refusal) => {
            tracing::error!("{refusal}");
            app.sanitize.refusal = Some(refusal.to_string());
            return;
        }
    };

    let cert_dir = PathBuf::from(match app.sanitize.cert_dir.trimmed() {
        "" => ".",
        d => d,
    });
    let cancel = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(engine::Progress::default());
    app.sanitize_job = Some(SanitizeJob {
        cancel: cancel.clone(),
        progress: progress.clone(),
        started: Instant::now(),
        device: selected.path.clone(),
        method: clearance.method().label(),
        dry_run: clearance.is_dry_run(),
    });
    app.sanitize.last = None;
    app.sanitize.refusal = None;
    app.sanitize.view = View::Progress;

    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = run(clearance, &cert_dir, &cancel, &progress).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::SanitizeDone(Box::new(r)));
    });
}

/// The same sequence `arachnid-sanitize wipe` performs, through the same
/// library calls. Nothing here re-implements a rail, a pattern or a check.
fn run(
    clearance: safety::Clearance,
    cert_dir: &std::path::Path,
    cancel: &AtomicBool,
    progress: &engine::Progress,
) -> Result<Done> {
    let device = clearance.device().clone();

    // A dry run must not open the device for writing at all; opening a raw
    // handle is itself an effect on the system.
    if clearance.is_dry_run() {
        let outcome = engine::WipeOutcome {
            method: clearance.method(),
            purge_path: arachnid_sanitize_core::purge::PurgeOutcome::NotAttempted {
                capability: arachnid_sanitize_core::purge::probe(&device),
            },
            passes: Vec::new(),
            bytes_written: 0,
            bytes_total: device.size_bytes,
            started_utc: arachnid_evidence::now_utc(),
            finished_utc: arachnid_evidence::now_utc(),
            duration_secs: 0.0,
            bad_region_count: 0,
            bad_regions: Vec::new(),
            cancelled: false,
            dry_run: true,
        };
        return Ok(Done {
            device,
            verification: verify::VerifyReport {
                passed: false,
                bytes_sampled: 0,
                device_size: 0,
                samples: Vec::new(),
                blocked: Some("dry run: nothing was written".into()),
            },
            outcome,
            certificate: None,
            refused: Some("dry run: no certificate is issued".into()),
            register: cert_dir.join(arachnid_sanitize_core::REGISTER_FILE),
            fingerprint: String::new(),
        });
    }

    let mut target = RawDeviceTarget::open(&device.path).with_context(|| {
        format!(
            "open {} for writing (needs Administrator on Windows, root on Linux)",
            device.path
        )
    })?;

    let outcome = engine::wipe(&mut target, &clearance, progress, cancel)?;
    let verification = verify::verify(&mut target, &outcome, &verify::VerifyOptions::default())?;

    let key = cert::ephemeral_key()?;
    let fingerprint = cert::key_fingerprint(&key);
    let register = cert_dir.join(arachnid_sanitize_core::REGISTER_FILE);
    let prev = cert::head(&register)?;

    let (certificate, refused) = match cert::issue(&clearance, &outcome, &verification, &key, &prev)
    {
        Ok(c) => {
            cert::append(&register, &c, &key)?;
            (Some(c), None)
        }
        Err(r) => (None, Some(r.to_string())),
    };

    Ok(Done {
        device,
        outcome,
        verification,
        certificate,
        refused,
        register,
        fingerprint,
    })
}

pub fn cancel(app: &mut App) {
    if let Some(j) = &app.sanitize_job {
        j.cancel.store(true, Ordering::Relaxed);
        app.toast("cancelling wipe at the next chunk boundary", false);
    }
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    app.sanitize_job = None;
    match result {
        Ok(done) => {
            let msg = match (&done.certificate, &done.refused) {
                (Some(c), _) => format!("erased and certified — {}", c.certificate_id),
                (None, Some(why)) => why.clone(),
                (None, None) => "wipe finished".into(),
            };
            app.toast(msg, done.certificate.is_none());
            app.sanitize.view = View::Result;
            app.sanitize.last = Some(done);
        }
        Err(e) => {
            app.toast(e, true);
            app.sanitize.view = View::Devices;
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.sanitize.view {
        View::Devices => render_devices(frame, area, app),
        View::Method => render_method(frame, area, app),
        View::Confirm => render_confirm(frame, area, app),
        View::Progress => render_progress(frame, area, app),
        View::Result => render_result(frame, area, app),
    }
}

/// The refusal banner, drawn under whichever view raised it.
fn refusal_lines(app: &App) -> Vec<Line<'static>> {
    let t = Theme::get();
    match &app.sanitize.refusal {
        None => Vec::new(),
        Some(r) => vec![Line::from(vec![
            Span::styled(
                " REFUSED ",
                Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
            ),
            Span::raw(r.clone()),
        ])],
    }
}

fn render_devices(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.sanitize;

    let [head, table, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(if s.refusal.is_some() { 3 } else { 2 }),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " SANITIZE ",
                    Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
                ),
                Span::raw("irreversible data destruction — every other screen here is read-only"),
            ]),
            Line::from(ui::dim(if s.enumerating {
                " enumerating devices…"
            } else {
                " r re-enumerate  ·  Enter select a device  ·  f permit system disks"
            })),
        ]),
        head,
    );

    let w = table.width as usize;
    let mut lines = vec![Line::from(ui::dim(format!(
        "  {:<20}{:<24}{:<20}{:>10}  {:<7}{}",
        "path", "model", "serial", "size", "bus", "flags"
    )))];

    if s.devices.is_empty() {
        lines.push(Line::from(ui::dim(if s.enumerating {
            "  …"
        } else {
            "  no devices — press r to enumerate (needs Administrator/root)"
        })));
    }

    let rows = table.height.saturating_sub(1) as usize;
    let start = window(s.sel, rows, s.devices.len());
    for (i, d) in s.devices.iter().enumerate().skip(start).take(rows) {
        let mut flags = Vec::new();
        if d.is_system {
            flags.push("SYSTEM");
        }
        if d.removable {
            flags.push("removable");
        }
        let text = format!(
            "  {:<20}{:<24}{:<20}{:>10}  {:<7}{}",
            ui::ellipsis(&d.path, 19),
            ui::ellipsis(&d.model, 23),
            ui::ellipsis(
                if d.serial.is_empty() {
                    "(none)"
                } else {
                    &d.serial
                },
                19
            ),
            d.size_human(),
            d.bus.label(),
            flags.join(", ")
        );
        // A system disk is red on every row, selected or not: it must not be
        // possible to skim this table and miss which row is the running OS.
        let mut style = if d.is_system {
            Style::new().fg(t.bad).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        if i == s.sel {
            style = style.patch(t.selected());
        }
        lines.push(Line::from(Span::styled(ui::ellipsis(&text, w), style)));
    }
    frame.render_widget(Paragraph::new(lines), table);

    let mut bottom = refusal_lines(app);
    bottom.push(Line::from(ui::dim(format!(
        " system-disk wipes: {}",
        if app.sanitize.force_system {
            "PERMITTED for this session (f to revoke)"
        } else {
            "blocked (f to permit)"
        }
    ))));
    if let Some(d) = app.sanitize.selected() {
        if let Some(r) = &d.system_reason {
            bottom.push(Line::from(ui::dim(format!(" selected: {r}"))));
        }
    }
    frame.render_widget(Paragraph::new(bottom).wrap(Wrap { trim: true }), foot);
}

fn render_method(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.sanitize;
    let Some(d) = s.selected() else {
        app.sanitize.view = View::Devices;
        return;
    };

    let [head, list, detail] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(METHODS.len() as u16 + 1),
        Constraint::Min(3),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                ui::dim(" device  "),
                Span::raw(format!("{} — {} ({})", d.path, d.model, d.size_human())),
            ]),
            Line::from(ui::dim(
                " choose a method — the choice decides what the certificate can claim",
            )),
        ]),
        head,
    );

    let mut lines = Vec::new();
    for (i, m) in METHODS.iter().enumerate() {
        let selected = i == s.method;
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} {:<26}", if selected { ">" } else { " " }, m.label()),
                if selected { t.selected() } else { t.dimmed() },
            ),
            ui::dim(format!(
                "{} pass(es){}",
                m.passes().len(),
                if m.tries_hardware_first() {
                    ", hardware first"
                } else {
                    ""
                }
            )),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), list);

    let m = s.method();
    let estimate = estimate_for(d, m);
    let mut body = vec![
        Line::from(Span::styled(m.label().to_string(), t.selected())),
        Line::raw(""),
        Line::raw(m.explanation().to_string()),
        Line::raw(""),
        Line::from(vec![
            ui::dim("estimated duration for this device  "),
            Span::raw(hms(estimate)),
            ui::dim("   (pessimistic)"),
        ]),
    ];
    if m.tries_hardware_first() {
        body.push(Line::from(Span::styled(
            "This build issues no hardware sanitize command. A software overwrite will run and \
             the certificate will state that plainly.",
            Style::new().fg(t.warn),
        )));
    }
    if m == WipeMethod::CryptoErase {
        body.push(Line::from(Span::styled(
            "Crypto-erase is refused on every device in this build: a self-encrypting drive \
             cannot be confirmed as one over the pass-through path this build implements.",
            Style::new().fg(t.bad),
        )));
    }
    body.push(Line::raw(""));
    body.push(Line::from(ui::dim("Enter continue  ·  Esc back")));
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: true }), detail);
}

fn estimate_for(d: &Device, m: WipeMethod) -> Duration {
    // Mirrors engine::estimate, which needs a Clearance this view does not have
    // yet. Kept in step by reading the same pass count off the same method.
    let per_sec: u64 = match d.bus {
        arachnid_sanitize_core::BusType::Nvme => 1_200_000_000,
        arachnid_sanitize_core::BusType::Sata | arachnid_sanitize_core::BusType::Sas => 400_000_000,
        arachnid_sanitize_core::BusType::Usb => 80_000_000,
        _ => 200_000_000,
    };
    let passes = m.passes().len().max(1) as u64;
    Duration::from_secs(d.size_bytes.saturating_mul(passes) / per_sec.max(1))
}

/// The confirm view. Structurally unlike `ui::confirm`: a full-screen bordered
/// panel in the failure colour, an explicit banner, a typed serial, and a
/// commit key that is not the one the ordinary dialog uses.
fn render_confirm(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.sanitize;
    let Some(d) = s.selected().cloned() else {
        app.sanitize.view = View::Devices;
        return;
    };
    let m = s.method();

    let block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(Style::new().fg(t.bad).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            " IRREVERSIBLE DATA DESTRUCTION ",
            Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [summary, fields, gate] = Layout::vertical([
        Constraint::Min(6),
        Constraint::Length(CONFIRM_FIELDS as u16 + 1),
        Constraint::Length(4),
    ])
    .areas(inner);

    let matches = s.serial.trimmed() == d.serial.trim() && !d.serial.trim().is_empty();
    let mut body = vec![
        Line::from(vec![
            ui::dim(" device   "),
            Span::raw(format!("{} — {}", d.path, d.model)),
        ]),
        Line::from(vec![
            ui::dim(" serial   "),
            Span::styled(d.serial.clone(), Style::new().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            ui::dim(" capacity "),
            Span::raw(d.size_human()),
            ui::dim("    bus "),
            Span::raw(d.bus.label().to_string()),
        ]),
        Line::from(vec![
            ui::dim(" method   "),
            Span::raw(format!("{} — {} pass(es)", m.label(), m.passes().len())),
        ]),
        Line::from(vec![
            ui::dim(" estimate "),
            Span::raw(hms(estimate_for(&d, m))),
        ]),
    ];
    if d.is_system {
        body.push(Line::from(Span::styled(
            " THIS DEVICE HOSTS THE RUNNING OPERATING SYSTEM. Wiping it destroys this machine.",
            Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
        )));
    }
    if d.removable {
        body.push(Line::from(Span::styled(
            " Removable device: confirm it is still the drive you selected before committing.",
            Style::new().fg(t.warn),
        )));
    }
    body.extend(refusal_lines(app));
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: true }), summary);

    let rows: [Rect; CONFIRM_FIELDS + 1] =
        Layout::vertical([Constraint::Length(1); CONFIRM_FIELDS + 1]).areas(fields);
    ui::field(
        frame,
        rows[0],
        "type serial",
        &s.serial.value,
        s.field == 0,
        app.editing && s.field == 0,
    );
    ui::field(
        frame,
        rows[1],
        "certificates",
        &s.cert_dir.value,
        s.field == 1,
        app.editing && s.field == 1,
    );
    frame.render_widget(
        Paragraph::new(Line::from(if matches {
            Span::styled("  serial matches", t.verdict(true))
        } else {
            Span::styled("  serial does not match the device above", t.verdict(false))
        })),
        rows[2],
    );

    let cooldown = s.cooldown_remaining();
    let mut tail = vec![Line::from(vec![
        ui::dim(" mode  "),
        Span::styled(
            if s.dry_run {
                "DRY RUN — nothing will be written"
            } else {
                "LIVE — the device will be destroyed"
            },
            if s.dry_run {
                t.verdict(true)
            } else {
                Style::new().fg(t.bad).add_modifier(Modifier::BOLD)
            },
        ),
        ui::dim("   (d toggles)"),
    ])];
    tail.push(match cooldown {
        Some(left) => Line::from(Span::styled(
            format!(
                " wait {:.0}s — read the summary above",
                left.as_secs_f64().ceil()
            ),
            Style::new().fg(t.warn),
        )),
        None if !matches => Line::from(ui::dim(" type the serial exactly as shown to continue")),
        None => Line::from(Span::styled(
            if s.dry_run {
                " press SHIFT-W to run the dry run"
            } else {
                " press SHIFT-W to BEGIN DESTROYING DATA"
            },
            Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
        )),
    });
    tail.push(Line::from(ui::dim(
        " Tab/j/k field  ·  Enter edit  ·  Esc back",
    )));
    frame.render_widget(Paragraph::new(tail), gate);
}

fn render_progress(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let Some(j) = &app.sanitize_job else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(
                " no wipe running — Esc to the device list",
            ))),
            area,
        );
        return;
    };

    let elapsed = j.started.elapsed();
    let done = j.progress.bytes_written.load(Ordering::Relaxed);
    let total = j.progress.bytes_total.load(Ordering::Relaxed);
    let pass = j.progress.pass.load(Ordering::Relaxed);
    let passes = j.progress.passes_total.load(Ordering::Relaxed);
    let bad = j.progress.bad_regions.load(Ordering::Relaxed);
    let fraction = j.progress.fraction();
    let width = (area.width as usize).saturating_sub(12).min(60);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} wiping ", app.spinner()), t.verdict(false)),
            Span::raw(format!("{} — {}", j.device, j.method)),
            if j.dry_run {
                Span::styled("  [dry run]", t.verdict(true))
            } else {
                ui::dim("")
            },
        ]),
        Line::raw(""),
        Line::from(vec![
            ui::dim(" pass      "),
            Span::raw(format!("{pass} of {passes}")),
        ]),
        Line::from(vec![
            ui::dim(" written   "),
            Span::raw(format!(
                "{} of {}  ({:.1}%)",
                device::human_bytes(done),
                device::human_bytes(total),
                fraction * 100.0
            )),
        ]),
        {
            let filled = ui::bar(done, total.max(1), width);
            let rest = width.saturating_sub(filled.chars().count());
            Line::from(vec![
                ui::dim(" progress  ["),
                Span::raw(filled),
                ui::dim("·".repeat(rest)),
                ui::dim("]"),
            ])
        },
        Line::from(vec![
            ui::dim(" rate      "),
            Span::raw(format!(
                "{}/s",
                device::human_bytes(j.progress.throughput_bytes_per_sec(elapsed) as u64)
            )),
            ui::dim("    elapsed "),
            Span::raw(hms(elapsed)),
            ui::dim("    eta "),
            Span::raw(
                j.progress
                    .eta(elapsed)
                    .map(hms)
                    .unwrap_or_else(|| "estimating…".into()),
            ),
        ]),
    ];
    if bad > 0 {
        lines.push(Line::from(Span::styled(
            format!(" {bad} unwritable region(s) so far — this wipe cannot be certified"),
            t.verdict(false),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(ui::dim(
        " this job keeps running if you switch screens  ·  x cancel  ·  Esc device list",
    )));
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_result(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let Some(d) = &app.sanitize.last else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(" no wipe from this session yet."))),
            area,
        );
        return;
    };

    let certified = d.certificate.is_some();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(
                    " {} ",
                    if certified {
                        "CERTIFIED"
                    } else {
                        "NOT CERTIFIED"
                    }
                ),
                t.verdict(certified),
            ),
            Span::raw(format!("{} — {}", d.device.path, d.device.model)),
        ]),
        Line::from(vec![
            ui::dim(" method    "),
            Span::raw(d.outcome.method.label().to_string()),
            ui::dim("    passes "),
            Span::raw(format!("{}", d.outcome.passes.len())),
        ]),
        Line::from(vec![
            ui::dim(" written   "),
            Span::raw(format!(
                "{} of {}",
                device::human_bytes(d.outcome.bytes_written),
                device::human_bytes(d.outcome.bytes_total)
            )),
            ui::dim("    duration "),
            Span::raw(format!("{:.1}s", d.outcome.duration_secs)),
        ]),
    ];

    if let Some(why) = &d.refused {
        lines.push(Line::from(Span::styled(
            format!(" {why}"),
            t.verdict(false),
        )));
    }

    let v = &d.verification;
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        ui::dim(" verification  "),
        Span::styled(
            match &v.blocked {
                Some(b) => format!("not run — {b}"),
                None if v.passed => format!(
                    "PASSED — {} region(s), {} read back ({:.4}% of the device)",
                    v.samples.len(),
                    device::human_bytes(v.bytes_sampled),
                    v.coverage() * 100.0
                ),
                None => format!("FAILED — {} region(s) mismatched", v.failures().count()),
            },
            t.verdict(v.passed),
        ),
    ]));
    for f in v.failures().take(4) {
        lines.push(Line::from(Span::styled(
            format!(
                "   offset {}: expected {}, found {}",
                f.first_mismatch_at.unwrap_or(f.offset),
                f.expected_hex.as_deref().unwrap_or("?"),
                f.observed_hex.as_deref().unwrap_or("?")
            ),
            t.verdict(false),
        )));
    }
    for b in d.outcome.bad_regions.iter().take(4) {
        lines.push(Line::from(Span::styled(
            format!(
                "   unwritable at offset {} ({} bytes, pass {}): {}",
                b.offset, b.length, b.pass, b.error
            ),
            t.verdict(false),
        )));
    }

    if let Some(c) = &d.certificate {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            ui::dim(" certificate  "),
            Span::raw(c.certificate_id.clone()),
        ]));
        lines.push(Line::from(vec![
            ui::dim(" claim        "),
            Span::raw(c.method_detail.clone()),
        ]));
        lines.push(Line::from(vec![
            ui::dim(" register     "),
            Span::raw(d.register.display().to_string()),
        ]));
        lines.push(Line::from(vec![
            ui::dim(" key sha256   "),
            Span::raw(d.fingerprint.clone()),
        ]));
        lines.push(Line::from(ui::dim(
            " record that fingerprint out-of-band; verification proves origin only against it",
        )));
        lines.push(Line::raw(""));
        lines.push(Line::from(ui::dim(
            " e export the certificate as Markdown and HTML  ·  Esc device list",
        )));
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::from(ui::dim(" Esc device list")));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn window(sel: usize, rows: usize, len: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    sel.saturating_sub(rows - 1).min(len - rows)
}
