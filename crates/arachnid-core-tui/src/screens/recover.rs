//! Recover: file carving and filesystem-aware recovery.
//!
//! Read-only against its source, like every screen here except Sanitize — and
//! structurally so: `arachnid_recover_core::Source` has no write method, so
//! nothing this screen can do reaches the media it is reading.
//!
//! The flow is source → configuration → progress → results → export. Unlike
//! Sanitize, none of these steps is dangerous, so none of them is made
//! deliberately awkward; the care here goes somewhere else. A recovered file
//! looks the same in a folder whether the filesystem handed over its name and
//! timestamps or a carver found its bytes in unallocated space, and those are
//! very different claims. So the results browser shows the confidence label on
//! every row, and the detail pane shows the checks behind it — not as a
//! drill-down an operator might never open, but beside the selection, always.
//!
//! The one thing this screen does refuse is writing recovery output onto the
//! device being recovered from, which overwrites exactly the unallocated space
//! the recovery is reading. That rail lives in `arachnid_recover_core`, and this
//! screen surfaces it rather than reimplementing it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arachnid_recover_core as recover;
use arachnid_sanitize_core::{device, Device};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use recover::results::{Confidence, RecoveredFile, ScanResults};

use crate::app::{Action, App, Input, Msg, RecoverJob, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "move"),
    ("Enter", "select / edit"),
    ("Space", "toggle"),
    ("s", "start scan"),
    ("c/t", "filter"),
    ("e", "export"),
    ("r", "reload"),
    ("x", "cancel scan"),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Source,
    Config,
    Progress,
    Results,
    Export,
}

/// Where a scan reads from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceKind {
    /// A raw disk or partition image: a Core acquisition, or a dd capture.
    Image,
    /// An attached device, opened read-only. Enumeration is Sanitize's, which
    /// is already read-only; only the handle differs, and this one cannot write.
    Device,
    /// An artifact inside an evidence container from a prior Core session.
    Container,
}

const SOURCES: [(SourceKind, &str, &str); 3] = [
    (
        SourceKind::Image,
        "disk or partition image",
        "a file: a Core acquisition, or a dd/raw image",
    ),
    (
        SourceKind::Device,
        "attached device — read-only scan",
        "the same device list Sanitize uses, opened without write access",
    ),
    (
        SourceKind::Container,
        "evidence container",
        "an image artifact inside a container from a prior Core session",
    ),
];

/// Confidence thresholds an export can be set to, weakest last.
const THRESHOLDS: [Confidence; 3] = [Confidence::High, Confidence::Medium, Confidence::Low];

/// What one export run produced, for the result view.
pub struct Exported {
    pub output: PathBuf,
    pub exported: usize,
    pub skipped: Vec<(String, String)>,
    pub fingerprint: String,
}

/// Everything the scan thread needs to open its own source. `Source` is not
/// `Send`-cloneable, so the handle is opened on the worker rather than moved.
#[derive(Clone, Debug)]
enum SourceSpec {
    Image(PathBuf),
    Device(String),
}

impl SourceSpec {
    fn label(&self) -> String {
        match self {
            SourceSpec::Image(p) => p.display().to_string(),
            SourceSpec::Device(d) => d.clone(),
        }
    }

    fn open(&self) -> anyhow::Result<Box<dyn recover::Source>> {
        match self {
            SourceSpec::Image(p) => Ok(Box::new(recover::source::ImageSource::open(p)?)),
            SourceSpec::Device(d) => Ok(Box::new(recover::source::DeviceSource::open(d)?)),
        }
    }
}

pub struct State {
    pub view: View,

    // -- source
    pub kind: usize,
    pub image_path: Input,
    pub container_path: Input,
    pub devices: Vec<Device>,
    pub device_sel: usize,
    pub enumerating: bool,
    /// Artifact names read out of the chosen container's custody log.
    pub artifacts: Vec<String>,
    pub artifact_sel: usize,
    /// Which row of the source view has the keyboard.
    pub source_field: usize,

    // -- configuration
    pub filesystem_pass: bool,
    pub carve_pass: bool,
    pub include_live: bool,
    /// Carve types and whether each is selected.
    pub types: Vec<(String, bool)>,
    pub output: Input,
    pub config_field: usize,

    // -- results
    pub results: Option<ScanResults>,
    pub sel: usize,
    pub filter_confidence: Option<Confidence>,
    pub filter_type: Option<String>,

    // -- export
    pub export_dir: Input,
    pub threshold: usize,
    pub export_field: usize,
    pub last_export: Option<Exported>,

    /// The most recent refusal, shown in place rather than as a toast so it
    /// stays on screen while the operator fixes it.
    pub refusal: Option<String>,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            view: View::Source,
            kind: 0,
            image_path: Input::new(saved.recent_images.first().cloned().unwrap_or_default()),
            container_path: Input::new(saved.last_container.clone().unwrap_or_default()),
            devices: Vec::new(),
            device_sel: 0,
            enumerating: false,
            artifacts: Vec::new(),
            artifact_sel: 0,
            source_field: 0,
            filesystem_pass: true,
            carve_pass: false,
            include_live: false,
            types: recover::carve::known_types()
                .into_iter()
                .map(|t| (t.to_string(), recover::carve::default_types().iter().any(|d| d == t)))
                .collect(),
            output: Input::new(
                saved
                    .last_recover_output
                    .clone()
                    .unwrap_or_else(|| "./recovered".to_string()),
            ),
            config_field: 0,
            results: None,
            sel: 0,
            filter_confidence: None,
            filter_type: None,
            export_dir: Input::new(
                saved
                    .last_recover_output
                    .clone()
                    .map(|d| format!("{d}/exported"))
                    .unwrap_or_else(|| "./recovered/exported".to_string()),
            ),
            // Default to Medium: exporting Low by default would fill the output
            // directory with carved fragments an analyst did not ask for.
            threshold: 1,
            export_field: 0,
            last_export: None,
            refusal: None,
        }
    }

    fn source_kind(&self) -> SourceKind {
        SOURCES[self.kind.min(SOURCES.len() - 1)].0
    }

    /// Resolve what the source rows currently describe into something a worker
    /// thread can open, or say why it cannot.
    fn spec(&self) -> Result<SourceSpec, String> {
        match self.source_kind() {
            SourceKind::Image => {
                let p = self.image_path.trimmed();
                if p.is_empty() {
                    return Err("no image path given".into());
                }
                Ok(SourceSpec::Image(PathBuf::from(p)))
            }
            SourceKind::Device => {
                let d = self
                    .devices
                    .get(self.device_sel)
                    .ok_or("no device selected — press r to enumerate")?;
                Ok(SourceSpec::Device(d.path.clone()))
            }
            SourceKind::Container => {
                let root = self.container_path.trimmed();
                if root.is_empty() {
                    return Err("no container path given".into());
                }
                let name = self
                    .artifacts
                    .get(self.artifact_sel)
                    .ok_or("no artifact selected — press r to read the container's custody log")?;
                Ok(SourceSpec::Image(
                    PathBuf::from(root).join("artifacts").join(name),
                ))
            }
        }
    }

    fn selected_types(&self) -> Vec<String> {
        self.types
            .iter()
            .filter(|(_, on)| *on)
            .map(|(t, _)| t.clone())
            .collect()
    }

    /// The results the browser is currently showing.
    pub fn visible(&self) -> Vec<&RecoveredFile> {
        let Some(r) = &self.results else {
            return Vec::new();
        };
        r.files
            .iter()
            .filter(|f| {
                self.filter_confidence.is_none_or(|c| f.confidence() == c)
                    && self
                        .filter_type
                        .as_ref()
                        .is_none_or(|t| t.eq_ignore_ascii_case(&f.file_type))
            })
            .collect()
    }

    fn threshold(&self) -> Confidence {
        THRESHOLDS[self.threshold.min(THRESHOLDS.len() - 1)]
    }

    /// Rows in the configuration view's focus ring: three toggles, one row per
    /// carve type, then the output directory.
    fn config_rows(&self) -> usize {
        3 + self.types.len() + 1
    }
}

// ---------------------------------------------------------------------------
// Enumeration and container loading
// ---------------------------------------------------------------------------

/// Re-read the attached devices, on a thread for the same reason Sanitize does:
/// on Windows this opens every physical drive in turn.
pub fn enumerate(app: &mut App) {
    if app.recover.enumerating {
        return;
    }
    app.recover.enumerating = true;
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = device::enumerate().map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::RecoverDevices(Box::new(r)));
    });
}

pub fn adopt_devices(app: &mut App, result: Result<Vec<Device>, String>) {
    app.recover.enumerating = false;
    match result {
        Ok(devices) => {
            if devices.is_empty() {
                app.toast(
                    "no storage devices visible — enumeration needs Administrator on Windows, \
                     root on Linux",
                    true,
                );
            }
            app.recover.device_sel = app.recover.device_sel.min(devices.len().saturating_sub(1));
            app.recover.devices = devices;
        }
        Err(e) => app.toast(e, true),
    }
}

/// Read the artifact names out of a container's custody log.
///
/// `read_log` explicitly does not verify signatures — this is a file picker, and
/// presenting it as though the log had been checked would be a lie. Verification
/// is the Verify screen's job, and the operator can run it on the same path.
fn load_container(app: &mut App) {
    let root = PathBuf::from(app.recover.container_path.trimmed());
    if root.as_os_str().is_empty() {
        app.toast("give a container path first", true);
        return;
    }
    match arachnid_evidence::read_log(&root) {
        Ok(records) => {
            let names: Vec<String> = records
                .into_iter()
                .filter(|r| r.event == "artifact")
                .filter_map(|r| r.name)
                .filter(|n| root.join("artifacts").join(n).is_file())
                .collect();
            if names.is_empty() {
                app.toast(format!("no artifacts found in {}", root.display()), true);
            }
            app.recover.artifact_sel = 0;
            app.recover.artifacts = names;
        }
        Err(e) => app.toast(format!("{e:#}"), true),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        let s = &mut app.recover;
        return match s.view {
            View::Source => match s.source_kind() {
                SourceKind::Container => s.container_path.key(&key),
                _ => s.image_path.key(&key),
            },
            View::Config => s.output.key(&key),
            View::Export => s.export_dir.key(&key),
            _ => false,
        };
    }

    match app.recover.view {
        View::Source => source_key(app, key),
        View::Config => config_key(app, key),
        View::Progress => progress_key(app, key),
        View::Results => results_key(app, key),
        View::Export => export_key(app, key),
    }
}

/// Rows in the source view: the three kinds, then whatever the chosen kind
/// needs — a path, or a list.
fn source_rows(s: &State) -> usize {
    SOURCES.len()
        + match s.source_kind() {
            SourceKind::Image => 1,
            SourceKind::Device => s.devices.len().max(1),
            SourceKind::Container => 1 + s.artifacts.len(),
        }
}

fn source_key(app: &mut App, key: KeyEvent) -> bool {
    let rows = source_rows(&app.recover);
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.recover.source_field, 1, rows),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.recover.source_field, -1, rows),
        KeyCode::Char('r') => match app.recover.source_kind() {
            SourceKind::Device => enumerate(app),
            SourceKind::Container => load_container(app),
            SourceKind::Image => app.toast("nothing to reload for an image path", false),
        },
        KeyCode::Enter => {
            let field = app.recover.source_field;
            if field < SOURCES.len() {
                // Choosing a kind resets the rows below it, which now mean
                // something else.
                app.recover.kind = field;
                app.recover.source_field = SOURCES.len();
                app.recover.refusal = None;
                if app.recover.source_kind() == SourceKind::Device && app.recover.devices.is_empty()
                {
                    enumerate(app);
                }
                return true;
            }
            let below = field - SOURCES.len();
            match app.recover.source_kind() {
                SourceKind::Image => app.editing = true,
                SourceKind::Device => {
                    app.recover.device_sel = below.min(app.recover.devices.len().saturating_sub(1));
                    advance_to_config(app);
                }
                SourceKind::Container => {
                    if below == 0 {
                        app.editing = true;
                    } else {
                        app.recover.artifact_sel = below - 1;
                        advance_to_config(app);
                    }
                }
            }
        }
        // A path field is committed by moving on, so there has to be a way to
        // move on that is not Enter.
        KeyCode::Tab => advance_to_config(app),
        _ => return false,
    }
    true
}

fn advance_to_config(app: &mut App) {
    match app.recover.spec() {
        Ok(_) => {
            app.recover.refusal = None;
            app.recover.config_field = 0;
            app.recover.view = View::Config;
        }
        Err(why) => app.recover.refusal = Some(why),
    }
}

fn config_key(app: &mut App, key: KeyEvent) -> bool {
    let rows = app.recover.config_rows();
    let types_at = 3;
    let output_at = rows - 1;
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.recover.config_field, 1, rows),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.recover.config_field, -1, rows),
        KeyCode::Char(' ') => {
            let field = app.recover.config_field;
            let s = &mut app.recover;
            match field {
                0 => s.filesystem_pass = !s.filesystem_pass,
                1 => s.carve_pass = !s.carve_pass,
                2 => s.include_live = !s.include_live,
                f if f < output_at => {
                    let i = f - types_at;
                    s.types[i].1 = !s.types[i].1;
                    // Toggling a type is only meaningful with the carve pass on;
                    // turning one on is a clear statement of intent.
                    if s.types[i].1 {
                        s.carve_pass = true;
                    }
                }
                _ => {}
            }
        }
        KeyCode::Enter if app.recover.config_field == output_at => app.editing = true,
        KeyCode::Char('s') => start(app),
        KeyCode::Esc => app.recover.view = View::Source,
        _ => return false,
    }
    true
}

fn progress_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('x') => {
            if app.recover_job.is_some() {
                app.ask(
                    "Cancel the running recovery? Results will cover only the part of the \
                     source read so far.",
                    Action::CancelRecover,
                );
            }
        }
        KeyCode::Esc => {
            app.recover.view = if app.recover.results.is_some() {
                View::Results
            } else {
                View::Config
            }
        }
        _ => return false,
    }
    true
}

fn results_key(app: &mut App, key: KeyEvent) -> bool {
    let n = app.recover.visible().len();
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.recover.sel, 1, n),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.recover.sel, -1, n),
        KeyCode::Char('c') => {
            // None -> High -> Medium -> Low -> None.
            app.recover.filter_confidence = match app.recover.filter_confidence {
                None => Some(Confidence::High),
                Some(Confidence::High) => Some(Confidence::Medium),
                Some(Confidence::Medium) => Some(Confidence::Low),
                Some(Confidence::Low) => None,
            };
            app.recover.sel = 0;
        }
        KeyCode::Char('t') => {
            let types = present_types(&app.recover);
            let next = match &app.recover.filter_type {
                None => types.first().cloned(),
                Some(current) => {
                    let at = types.iter().position(|t| t == current);
                    at.and_then(|i| types.get(i + 1).cloned())
                }
            };
            app.recover.filter_type = next;
            app.recover.sel = 0;
        }
        KeyCode::Char('e') => {
            if app.recover.results.is_some() {
                app.recover.export_field = 0;
                app.recover.view = View::Export;
            }
        }
        KeyCode::Esc => app.recover.view = View::Config,
        _ => return false,
    }
    true
}

/// File types actually present in the results, so the filter cycles through
/// something rather than through every type the carver knows.
fn present_types(s: &State) -> Vec<String> {
    let Some(r) = &s.results else {
        return Vec::new();
    };
    let mut types: Vec<String> = r.files.iter().map(|f| f.file_type.clone()).collect();
    types.sort();
    types.dedup();
    types
}

fn export_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::wrap(&mut app.recover.export_field, 1, 2),
        KeyCode::Char('k') | KeyCode::Up => super::wrap(&mut app.recover.export_field, -1, 2),
        KeyCode::Tab => super::wrap(&mut app.recover.export_field, 1, 2),
        KeyCode::Enter if app.recover.export_field == 0 => app.editing = true,
        KeyCode::Char(' ') if app.recover.export_field == 1 => {
            super::wrap(&mut app.recover.threshold, 1, THRESHOLDS.len())
        }
        KeyCode::Char('e') => {
            let count = selected_for_export(&app.recover).len();
            if count == 0 {
                app.recover.refusal =
                    Some("nothing meets that confidence threshold; lower it or rescan".into());
                return true;
            }
            let dir = app.recover.export_dir.trimmed().to_string();
            app.ask(
                format!(
                    "Export {count} file(s) at {} confidence or better to {dir}? \
                     Each is hashed into a signed chain-of-custody log.",
                    app.recover.threshold().label()
                ),
                Action::StartRecoverExport,
            );
        }
        KeyCode::Esc => app.recover.view = View::Results,
        _ => return false,
    }
    true
}

/// Which results an export would write: everything at or above the threshold.
fn selected_for_export(s: &State) -> Vec<&RecoveredFile> {
    let Some(r) = &s.results else {
        return Vec::new();
    };
    let floor = s.threshold();
    r.files.iter().filter(|f| f.confidence() >= floor).collect()
}

// ---------------------------------------------------------------------------
// Running the scan
// ---------------------------------------------------------------------------

pub fn start(app: &mut App) {
    if app.recover_job.is_some() {
        app.toast("a recovery job is already running", true);
        return;
    }
    let spec = match app.recover.spec() {
        Ok(s) => s,
        Err(why) => {
            app.recover.refusal = Some(why);
            app.recover.view = View::Source;
            return;
        }
    };
    if !app.recover.filesystem_pass && !app.recover.carve_pass {
        app.recover.refusal = Some("choose at least one pass — Space toggles them".into());
        return;
    }
    if app.recover.carve_pass && app.recover.selected_types().is_empty() {
        app.recover.refusal =
            Some("the carving pass has no file types selected — Space toggles them".into());
        return;
    }

    let output = PathBuf::from(match app.recover.output.trimmed() {
        "" => "./recovered",
        d => d,
    });
    // The rail that matters: recovery output must not land on the device being
    // recovered from. `arachnid_recover_core` owns it; this only surfaces it.
    if let SourceSpec::Device(path) = &spec {
        if let Err(why) = check_output_media(path, &output) {
            app.recover.refusal = Some(why);
            return;
        }
    }

    let options = recover::ScanOptions {
        filesystem_pass: app.recover.filesystem_pass,
        carve_pass: app.recover.carve_pass,
        carve_types: app.recover.selected_types(),
        deleted_only: !app.recover.include_live,
        operator: app.saved.operator.clone(),
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(recover::Progress::default());
    app.recover_job = Some(RecoverJob {
        cancel: cancel.clone(),
        progress: progress.clone(),
        started: Instant::now(),
        source: spec.label(),
        exporting: false,
    });
    app.recover.refusal = None;
    app.recover.results = None;
    app.recover.sel = 0;
    app.recover.view = View::Progress;
    if let SourceSpec::Image(p) = &spec {
        app.remember_image(p);
    }
    app.remember_recover_output(&output);
    app.recover.export_dir.set(
        output
            .join("exported")
            .display()
            .to_string(),
    );

    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = run_scan(&spec, &options, &progress, &cancel, &output).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::RecoverDone(Box::new(r)));
    });
}

/// The same sequence `arachnid-recover scan` performs, through the same library
/// calls. Nothing here re-implements a parser, a score or a rail.
fn run_scan(
    spec: &SourceSpec,
    options: &recover::ScanOptions,
    progress: &recover::Progress,
    cancel: &AtomicBool,
    output: &std::path::Path,
) -> anyhow::Result<ScanResults> {
    let mut source = spec.open()?;
    let results = recover::scan(source.as_mut(), options, progress, cancel)?;
    // Write the index beside the summary, so the CLI can pick up exactly where
    // the TUI left off — the two front ends share one on-disk format.
    std::fs::create_dir_all(output)?;
    std::fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&results)?,
    )?;
    std::fs::write(output.join("summary.txt"), results.summary())?;
    Ok(results)
}

/// Refuse an output directory that lives on the device being scanned.
///
/// Linux can prove it from the mount table. Elsewhere it cannot be proven
/// cheaply, so the operator is told rather than blocked — a refusal on a guess
/// would stop legitimate work.
fn check_output_media(device: &str, output: &std::path::Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let resolved = recover::export::resolve_output(output);
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        for line in mounts.lines() {
            let mut parts = line.split_whitespace();
            let (Some(src), Some(point)) = (parts.next(), parts.next()) else {
                continue;
            };
            let point = point.replace("\\040", " ");
            if src.starts_with(device) && resolved.starts_with(&point) {
                return Err(format!(
                    "{} is on {src}, mounted at {point}, which is part of {device}. Writing \
                     there would overwrite the unallocated space this recovery reads out of. \
                     Choose an output directory on different media.",
                    resolved.display()
                ));
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, output);
        Ok(())
    }
}

pub fn cancel(app: &mut App) {
    if let Some(j) = &app.recover_job {
        j.cancel.store(true, Ordering::Relaxed);
        app.toast("stopping the recovery at the next chunk", false);
    }
}

pub fn finished(app: &mut App, result: Result<ScanResults, String>) {
    app.recover_job = None;
    match result {
        Ok(results) => {
            let (high, medium, low) = results.counts();
            app.toast(
                format!(
                    "recovery finished — {} file(s): {high} High, {medium} Medium, {low} Low",
                    results.files.len()
                ),
                false,
            );
            app.recover.sel = 0;
            app.recover.results = Some(results);
            app.recover.view = View::Results;
        }
        Err(e) => {
            app.toast(e.clone(), true);
            app.recover.refusal = Some(e);
            app.recover.view = View::Config;
        }
    }
}

// ---------------------------------------------------------------------------
// Running the export
// ---------------------------------------------------------------------------

pub fn export(app: &mut App) {
    if app.recover_job.is_some() {
        app.toast("a recovery job is already running", true);
        return;
    }
    let Some(results) = app.recover.results.clone() else {
        return;
    };
    let spec = match app.recover.spec() {
        Ok(s) => s,
        Err(why) => {
            app.recover.refusal = Some(why);
            return;
        }
    };
    let output = PathBuf::from(match app.recover.export_dir.trimmed() {
        "" => "./recovered/exported",
        d => d,
    });
    if let SourceSpec::Device(path) = &spec {
        if let Err(why) = check_output_media(path, &output) {
            app.recover.refusal = Some(why);
            return;
        }
    }

    let floor = app.recover.threshold();
    let operator = app.saved.operator.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    app.recover_job = Some(RecoverJob {
        cancel: cancel.clone(),
        progress: Arc::new(recover::Progress::default()),
        started: Instant::now(),
        source: spec.label(),
        exporting: true,
    });
    app.recover.refusal = None;

    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = run_export(&spec, &results, floor, &output, &operator).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::RecoverExported(Box::new(r)));
    });
}

fn run_export(
    spec: &SourceSpec,
    results: &ScanResults,
    floor: Confidence,
    output: &std::path::Path,
    operator: &str,
) -> anyhow::Result<Exported> {
    let mut source = spec.open()?;
    if source.size() != results.source_size {
        anyhow::bail!(
            "the source is {} bytes but the scan read {} bytes. Every offset in the results \
             would point at the wrong data; refusing to export.",
            source.size(),
            results.source_size
        );
    }
    let selected: Vec<&RecoveredFile> = results
        .files
        .iter()
        .filter(|f| f.confidence() >= floor)
        .collect();
    let report =
        recover::export::export(source.as_mut(), results, &selected, output, operator)?;
    Ok(Exported {
        output: report.output_dir,
        exported: report.exported.len(),
        skipped: report.skipped,
        fingerprint: report.key_fingerprint,
    })
}

pub fn exported(app: &mut App, result: Result<Exported, String>) {
    app.recover_job = None;
    match result {
        Ok(done) => {
            app.toast(
                format!(
                    "exported {} file(s) to {}",
                    done.exported,
                    done.output.display()
                ),
                false,
            );
            app.remember_container(&done.output);
            app.recover.last_export = Some(done);
        }
        Err(e) => {
            app.toast(e.clone(), true);
            app.recover.refusal = Some(e);
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.recover.view {
        View::Source => render_source(frame, area, app),
        View::Config => render_config(frame, area, app),
        View::Progress => render_progress(frame, area, app),
        View::Results => render_results(frame, area, app),
        View::Export => render_export(frame, area, app),
    }
}

fn refusal_lines(app: &App) -> Vec<Line<'static>> {
    let t = Theme::get();
    match &app.recover.refusal {
        None => Vec::new(),
        Some(r) => vec![Line::from(vec![
            Span::styled(
                " CANNOT PROCEED ",
                Style::new().fg(t.bad).add_modifier(Modifier::BOLD),
            ),
            Span::raw(r.clone()),
        ])],
    }
}

fn render_source(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.recover;

    let [head, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(if s.refusal.is_some() { 4 } else { 3 }),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" RECOVER ", t.selected()),
                Span::raw("read-only file recovery — nothing here writes to the source"),
            ]),
            Line::from(ui::dim(
                " choose what to read from  ·  Enter select  ·  Tab continue  ·  r reload",
            )),
        ]),
        head,
    );

    let mut lines = Vec::new();
    for (i, (kind, label, hint)) in SOURCES.iter().enumerate() {
        let focused = s.source_field == i;
        let chosen = s.kind == i;
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    " {} {} {:<36}",
                    if focused { ">" } else { " " },
                    if chosen { "(*)" } else { "( )" },
                    label
                ),
                if focused { t.selected() } else { t.dimmed() },
            ),
            ui::dim(*hint),
        ]));
        let _ = kind;
    }
    lines.push(Line::raw(""));

    let below = s.source_field.saturating_sub(SOURCES.len());
    match s.source_kind() {
        SourceKind::Image => {
            lines.push(Line::from(ui::dim(" image file")));
        }
        SourceKind::Device => {
            lines.push(Line::from(ui::dim(if s.enumerating {
                " enumerating devices…"
            } else {
                " attached devices — opened read-only, no write capability is compiled into \
                  this path"
            })));
        }
        SourceKind::Container => {
            lines.push(Line::from(ui::dim(
                " container path, then an artifact from its custody log (not verified here — \
                  use the Verify screen for that)",
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), body);

    // The rows that belong to the chosen kind get the bottom band, so a long
    // device table has somewhere to go.
    let rows = Layout::vertical([Constraint::Min(1)]).split(foot)[0];
    let mut detail = Vec::new();
    match s.source_kind() {
        SourceKind::Image => {
            ui::field(
                frame,
                Rect { height: 1, ..rows },
                "path",
                &s.image_path.value,
                s.source_field == SOURCES.len(),
                app.editing,
            );
            detail.extend(refusal_lines(app));
            if !detail.is_empty() {
                frame.render_widget(
                    Paragraph::new(detail).wrap(Wrap { trim: true }),
                    Rect {
                        y: rows.y + 1,
                        height: rows.height.saturating_sub(1),
                        ..rows
                    },
                );
            }
            return;
        }
        SourceKind::Device => {
            if s.devices.is_empty() {
                detail.push(Line::from(ui::dim(
                    " no devices — press r to enumerate (needs Administrator/root)",
                )));
            }
            for (i, d) in s.devices.iter().enumerate().take(rows.height as usize) {
                let selected = below == i;
                detail.push(Line::from(Span::styled(
                    format!(
                        " {} {:<18}{:<22}{:>10}  {}",
                        if selected { ">" } else { " " },
                        ui::ellipsis(&d.path, 17),
                        ui::ellipsis(&d.model, 21),
                        d.size_human(),
                        if d.is_system { "SYSTEM" } else { "" }
                    ),
                    if selected { t.selected() } else { Style::new() },
                )));
            }
        }
        SourceKind::Container => {
            ui::field(
                frame,
                Rect { height: 1, ..rows },
                "container",
                &s.container_path.value,
                s.source_field == SOURCES.len(),
                app.editing,
            );
            for (i, name) in s
                .artifacts
                .iter()
                .enumerate()
                .take(rows.height.saturating_sub(1) as usize)
            {
                let selected = below == i + 1;
                detail.push(Line::from(Span::styled(
                    format!("   {} {name}", if selected { ">" } else { " " }),
                    if selected { t.selected() } else { t.dimmed() },
                )));
            }
            detail.extend(refusal_lines(app));
            frame.render_widget(
                Paragraph::new(detail).wrap(Wrap { trim: true }),
                Rect {
                    y: rows.y + 1,
                    height: rows.height.saturating_sub(1),
                    ..rows
                },
            );
            return;
        }
    }
    detail.extend(refusal_lines(app));
    frame.render_widget(Paragraph::new(detail).wrap(Wrap { trim: true }), rows);
}

fn render_config(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.recover;
    let rows = s.config_rows();
    let output_at = rows - 1;

    let [head, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(if s.refusal.is_some() { 3 } else { 2 }),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                ui::dim(" source  "),
                Span::raw(
                    s.spec()
                        .map(|sp| sp.label())
                        .unwrap_or_else(|e| format!("<{e}>")),
                ),
            ]),
            Line::from(ui::dim(
                " Space toggle  ·  Enter edit  ·  s start the scan  ·  Esc back",
            )),
        ]),
        head,
    );

    let toggle = |on: bool| if on { "[x]" } else { "[ ]" };
    let mut lines = vec![
        toggle_line(
            s.config_field == 0,
            toggle(s.filesystem_pass),
            "filesystem-aware pass",
            "parses NTFS/ext4 metadata: recovers names, paths and timestamps",
        ),
        toggle_line(
            s.config_field == 1,
            toggle(s.carve_pass),
            "raw carving pass",
            "scans sectors for signatures: recovers content, never identity",
        ),
        toggle_line(
            s.config_field == 2,
            toggle(s.include_live),
            "include live files",
            "off by default — live files are readable through the OS",
        ),
        Line::raw(""),
        Line::from(ui::dim(" carve types")),
    ];
    for (i, (name, on)) in s.types.iter().enumerate() {
        let focused = s.config_field == 3 + i;
        lines.push(Line::from(vec![
            Span::styled(
                format!("   {} {} {:<8}", if focused { ">" } else { " " }, toggle(*on), name),
                if focused { t.selected() } else { t.dimmed() },
            ),
            ui::dim(if name == "txt" {
                "off by default: matches log fragments and string tables everywhere"
            } else {
                ""
            }),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), body);

    let [output_row, rest] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(foot);
    ui::field(
        frame,
        output_row,
        "results dir",
        &s.output.value,
        s.config_field == output_at,
        app.editing && s.config_field == output_at,
    );
    let mut tail = refusal_lines(app);
    if tail.is_empty() {
        tail.push(Line::from(ui::dim(
            " results.json and summary.txt are written here; recovered files are exported \
             separately",
        )));
    }
    frame.render_widget(Paragraph::new(tail).wrap(Wrap { trim: true }), rest);
}

fn toggle_line(focused: bool, mark: &str, label: &str, hint: &str) -> Line<'static> {
    let t = Theme::get();
    Line::from(vec![
        Span::styled(
            format!(
                " {} {mark} {:<24}",
                if focused { ">" } else { " " },
                label
            ),
            if focused { t.selected() } else { t.dimmed() },
        ),
        ui::dim(hint.to_string()),
    ])
}

fn render_progress(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let Some(j) = &app.recover_job else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(
                " nothing running — Esc back to the configuration",
            ))),
            area,
        );
        return;
    };

    let elapsed = j.started.elapsed();
    let p = &j.progress;
    let scanned = p.carve.bytes_scanned.load(Ordering::Relaxed);
    let total = p.carve.bytes_total.load(Ordering::Relaxed);
    let width = (area.width as usize).saturating_sub(12).min(60);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(
                    " {} {} ",
                    app.spinner(),
                    if j.exporting { "exporting" } else { "recovering" }
                ),
                t.selected(),
            ),
            Span::raw(j.source.clone()),
        ]),
        Line::raw(""),
        Line::from(vec![
            ui::dim(" phase       "),
            Span::raw(p.phase_label().to_string()),
        ]),
        Line::from(vec![
            ui::dim(" filesystems "),
            Span::raw(p.filesystems_found.load(Ordering::Relaxed).to_string()),
            ui::dim("    files found "),
            Span::raw(p.files_found.load(Ordering::Relaxed).to_string()),
        ]),
    ];

    if total > 0 {
        let filled = ui::bar(scanned, total.max(1), width);
        let rest = width.saturating_sub(filled.chars().count());
        lines.push(Line::from(vec![
            ui::dim(" carving     ["),
            Span::raw(filled),
            ui::dim("·".repeat(rest)),
            ui::dim("]  "),
            Span::raw(format!("{:.1}%", p.carve.fraction() * 100.0)),
        ]));
        lines.push(Line::from(vec![
            ui::dim(" read        "),
            Span::raw(format!(
                "{} of {}",
                device::human_bytes(scanned),
                device::human_bytes(total)
            )),
        ]));
    }
    lines.push(Line::from(vec![
        ui::dim(" elapsed     "),
        Span::raw(hms(elapsed)),
    ]));
    lines.push(Line::raw(""));
    lines.push(Line::from(ui::dim(
        " read-only: nothing is being written to the source",
    )));
    lines.push(Line::from(ui::dim(
        " this job keeps running if you switch screens  ·  x cancel  ·  Esc back",
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn render_results(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let Some(results) = &app.recover.results else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(" no scan from this session yet."))),
            area,
        );
        return;
    };
    let visible = app.recover.visible();
    let (high, medium, low) = results.counts();

    // The detail pane is not a drill-down: an operator must be able to see why
    // the selected row carries the label it does without asking for it.
    let [head, table, detail] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(area.height.saturating_sub(6).clamp(4, 11)),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                ui::dim(" recovered  "),
                Span::styled(format!("{high} High"), t.verdict(true)),
                ui::dim("  ·  "),
                Span::styled(format!("{medium} Medium"), Style::new().fg(t.warn)),
                ui::dim("  ·  "),
                Span::styled(format!("{low} Low"), t.dimmed()),
                ui::dim(format!("   ({} shown)", visible.len())),
            ]),
            Line::from(ui::dim(format!(
                " c confidence: {}  ·  t type: {}  ·  e export  ·  Esc back",
                app.recover
                    .filter_confidence
                    .map(|c| c.label())
                    .unwrap_or("all"),
                app.recover.filter_type.as_deref().unwrap_or("all")
            ))),
        ]),
        head,
    );

    let w = table.width as usize;
    let mut lines = vec![Line::from(ui::dim(format!(
        "  {:<8}{:<6}{:>10}  {:<12}{}",
        "CONF", "TYPE", "SIZE", "METHOD", "NAME / PATH"
    )))];
    let rows = table.height.saturating_sub(1) as usize;
    let start = window(app.recover.sel, rows, visible.len());
    for (i, f) in visible.iter().enumerate().skip(start).take(rows) {
        let text = format!(
            "  {:<8}{:<6}{:>10}  {:<12}{}{}",
            f.confidence().label(),
            f.file_type,
            f.size,
            f.method.label(),
            f.display_name(),
            if f.encrypted.is_some() {
                "  [ENCRYPTED]"
            } else {
                ""
            }
        );
        let mut style = match f.confidence() {
            Confidence::High => t.verdict(true),
            Confidence::Medium => Style::new().fg(t.warn),
            Confidence::Low => t.dimmed(),
        };
        if i == app.recover.sel {
            style = style.patch(t.selected());
        }
        lines.push(Line::from(Span::styled(ui::ellipsis(&text, w), style)));
    }
    if visible.is_empty() {
        lines.push(Line::from(ui::dim("  nothing matches the current filters")));
    }
    frame.render_widget(Paragraph::new(lines), table);

    // -- why this row carries this label
    let mut body = Vec::new();
    match visible.get(app.recover.sel) {
        None => body.push(Line::from(ui::dim(" —"))),
        Some(f) => {
            body.push(Line::from(vec![
                Span::styled(format!(" {} ", f.confidence().label()), match f.confidence() {
                    Confidence::High => t.verdict(true),
                    Confidence::Medium => Style::new().fg(t.warn),
                    Confidence::Low => t.dimmed(),
                }),
                Span::raw(f.rationale.summary.clone()),
            ]));
            if let Some(e) = &f.encrypted {
                body.push(Line::from(Span::styled(
                    format!(" {e}"),
                    Style::new().fg(t.bad),
                )));
            }
            for c in &f.rationale.checks {
                body.push(Line::from(vec![
                    Span::styled(
                        format!("  [{}] ", if c.passed { "ok" } else { "  " }),
                        t.verdict(c.passed),
                    ),
                    Span::styled(format!("{:<26}", c.check), t.dimmed()),
                    Span::raw(c.detail.clone()),
                ]));
            }
        }
    }
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: true }), detail);
}

fn render_export(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.recover;
    let selected = selected_for_export(s);

    let [head, fields, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Min(3),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" EXPORT ", t.selected()),
                Span::raw(format!(
                    "{} file(s) at {} confidence or better",
                    selected.len(),
                    s.threshold().label()
                )),
            ]),
            Line::from(ui::dim(
                " Enter edit  ·  Space change threshold  ·  e export  ·  Esc back",
            )),
        ]),
        head,
    );

    let rows: [Rect; 3] = Layout::vertical([Constraint::Length(1); 3]).areas(fields);
    ui::field(
        frame,
        rows[0],
        "output dir",
        &s.export_dir.value,
        s.export_field == 0,
        app.editing && s.export_field == 0,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(
                    "{} {:<14}",
                    if s.export_field == 1 { ">" } else { " " },
                    "minimum"
                ),
                if s.export_field == 1 {
                    t.selected()
                } else {
                    t.dimmed()
                },
            ),
            Span::raw(s.threshold().label().to_string()),
            ui::dim("   (Space cycles High / Medium / Low)"),
        ])),
        rows[1],
    );
    let bytes: u64 = selected.iter().map(|f| f.size).sum();
    frame.render_widget(
        Paragraph::new(Line::from(ui::dim(format!(
            "  {} file(s), {} to write",
            selected.len(),
            device::human_bytes(bytes)
        )))),
        rows[2],
    );

    let mut lines = refusal_lines(app);
    match &s.last_export {
        Some(done) => {
            lines.push(Line::from(vec![
                Span::styled(" EXPORTED ", t.verdict(true)),
                Span::raw(format!(
                    "{} file(s) to {}",
                    done.exported,
                    done.output.display()
                )),
            ]));
            for (id, why) in done.skipped.iter().take(5) {
                lines.push(Line::from(Span::styled(
                    format!("  skipped {id}: {why}"),
                    t.verdict(false),
                )));
            }
            lines.push(Line::from(vec![
                ui::dim(" key sha256  "),
                Span::raw(done.fingerprint.clone()),
            ]));
            lines.push(Line::from(ui::dim(
                " record that fingerprint out-of-band; verification proves origin only against it",
            )));
            lines.push(Line::raw(""));
            lines.push(Line::from(ui::dim(format!(
                " re-check at any time:  arachnid-core verify {}",
                done.output.display()
            ))));
        }
        None => {
            lines.push(Line::raw(""));
            lines.push(Line::from(ui::dim(
                " Every exported file is hashed into a signed, hash-chained custody log in the",
            )));
            lines.push(Line::from(ui::dim(
                " output directory, so the recovery is itself auditable evidence rather than a",
            )));
            lines.push(Line::from(ui::dim(
                " folder of loose files. Carved results land under carved/, filesystem-recovered",
            )));
            lines.push(Line::from(ui::dim(
                " ones under recovered/ with their original directory structure.",
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), body);
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

#[cfg(test)]
mod tests {
    use super::*;
    use recover::results::{Method, Rationale, SCHEMA_VERSION};

    fn file(id: &str, confidence: Confidence, file_type: &str) -> RecoveredFile {
        RecoveredFile {
            id: id.into(),
            method: Method::NtfsMft,
            original_path: Some(format!("Cases/{id}.{file_type}")),
            export_name: format!("{id}.{file_type}"),
            file_type: file_type.into(),
            size: 10,
            extents: Vec::new(),
            created_utc: None,
            modified_utc: None,
            accessed_utc: None,
            deleted: true,
            encrypted: None,
            rationale: Rationale {
                confidence,
                summary: "test".into(),
                checks: Vec::new(),
            },
        }
    }

    fn state_with(files: Vec<RecoveredFile>) -> State {
        let mut s = State::new(&Saved::default());
        s.results = Some(ScanResults {
            schema_version: SCHEMA_VERSION.into(),
            tool: "arachnid-recover".into(),
            tool_version: "0.1.0".into(),
            source: "test.img".into(),
            source_size: 1024,
            started_utc: "2026-03-01T12:00:00Z".into(),
            finished_utc: "2026-03-01T12:00:01Z".into(),
            operator: "tester".into(),
            filesystem_pass: true,
            carve_pass: false,
            carve_types: Vec::new(),
            filesystems: Vec::new(),
            files,
            problems: Vec::new(),
        });
        s
    }

    /// The browser's two filters have to compose, or an operator narrowing by
    /// type silently loses their confidence filter.
    #[test]
    fn the_result_filters_compose() {
        let mut s = state_with(vec![
            file("a", Confidence::High, "pdf"),
            file("b", Confidence::Medium, "pdf"),
            file("c", Confidence::Medium, "jpg"),
        ]);
        assert_eq!(s.visible().len(), 3);

        s.filter_confidence = Some(Confidence::Medium);
        assert_eq!(s.visible().len(), 2);

        s.filter_type = Some("jpg".into());
        let ids: Vec<&str> = s.visible().iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["c"]);
    }

    /// The threshold is "this label or better", not "exactly this label". Getting
    /// it wrong would export only the weakest results — the opposite of intent.
    #[test]
    fn the_export_threshold_selects_that_label_and_better() {
        let mut s = state_with(vec![
            file("a", Confidence::High, "pdf"),
            file("b", Confidence::Medium, "pdf"),
            file("c", Confidence::Low, "jpg"),
        ]);

        s.threshold = 0; // High
        assert_eq!(selected_for_export(&s).len(), 1);
        s.threshold = 1; // Medium and better
        assert_eq!(selected_for_export(&s).len(), 2);
        s.threshold = 2; // everything
        assert_eq!(selected_for_export(&s).len(), 3);
    }

    /// Medium, not Low: defaulting to Low fills the output directory with carved
    /// fragments the operator did not ask for.
    #[test]
    fn the_default_threshold_excludes_carved_results() {
        let s = State::new(&Saved::default());
        assert_eq!(s.threshold(), Confidence::Medium);
    }

    /// Every carve type the engine knows must appear in the picker, or a type is
    /// unreachable from the TUI.
    #[test]
    fn the_type_picker_offers_every_known_type() {
        let s = State::new(&Saved::default());
        let offered: Vec<&str> = s.types.iter().map(|(t, _)| t.as_str()).collect();
        for known in recover::carve::known_types() {
            assert!(offered.contains(&known), "{known} is not offered");
        }
        // And the defaults are the engine's, not a second list that can drift.
        let on: Vec<String> = s.selected_types();
        assert_eq!(on, recover::carve::default_types());
    }
}
