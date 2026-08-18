//! Application state, the screen state machine, and the keymap.
//!
//! The keymap in [`GLOBAL`] is the single source of truth: the help overlay and
//! the footer render its labels, and [`global_for`] dispatches by scanning the
//! same array. Adding a global binding is one entry; it cannot appear in the
//! help without working, or work without appearing.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arachnid_netcap as netcap;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

use crate::screens;

/// Where the operator is. `Splash` and `Custody` are part of the same machine as
/// the six tabs so there is exactly one place that says what is on screen.
///
/// Adding a module (Sanitize, Recover) is a variant here, an entry in [`TABS`],
/// and a `screens/` module — no existing screen changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppScreen {
    Splash,
    Dashboard,
    Collect,
    Capture,
    Parse,
    Verify,
    Report,
    /// The chain-of-custody log, reached from Verify and Report. Not a tab: it
    /// is a drill-down, and `Esc` returns to whichever screen opened it.
    Custody,
}

/// The numbered tabs, in `1`..`6` order.
pub const TABS: [AppScreen; 6] = [
    AppScreen::Dashboard,
    AppScreen::Collect,
    AppScreen::Capture,
    AppScreen::Parse,
    AppScreen::Verify,
    AppScreen::Report,
];

impl AppScreen {
    pub fn title(self) -> &'static str {
        match self {
            AppScreen::Splash => "arachnid",
            AppScreen::Dashboard => "Dashboard",
            AppScreen::Collect => "Collect",
            AppScreen::Capture => "Capture",
            AppScreen::Parse => "Parse PCAP",
            AppScreen::Verify => "Verify",
            AppScreen::Report => "Report",
            AppScreen::Custody => "Chain of custody",
        }
    }
}

// ---------------------------------------------------------------------------
// Keymap
// ---------------------------------------------------------------------------

/// One key a binding responds to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    pub code: KeyCode,
    pub ctrl: bool,
}

const fn k(code: KeyCode) -> Chord {
    Chord { code, ctrl: false }
}
const fn ctrl(code: KeyCode) -> Chord {
    Chord { code, ctrl: true }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Global {
    Next,
    Prev,
    Jump,
    Help,
    Log,
    Back,
    Quit,
}

/// A global binding: the keys that trigger it, the label the help shows, and
/// what it does.
pub struct Binding {
    pub chords: &'static [Chord],
    pub label: &'static str,
    pub desc: &'static str,
    pub action: Global,
}

/// Global keybindings. Rendered by the help overlay and dispatched by
/// [`global_for`]; keep the two adjacent so neither can drift.
pub const GLOBAL: &[Binding] = &[
    Binding {
        chords: &[k(KeyCode::Tab)],
        label: "Tab",
        desc: "next screen",
        action: Global::Next,
    },
    Binding {
        chords: &[k(KeyCode::BackTab)],
        label: "Shift-Tab",
        desc: "previous screen",
        action: Global::Prev,
    },
    Binding {
        chords: &[
            k(KeyCode::Char('1')),
            k(KeyCode::Char('2')),
            k(KeyCode::Char('3')),
            k(KeyCode::Char('4')),
            k(KeyCode::Char('5')),
            k(KeyCode::Char('6')),
        ],
        label: "1-6",
        desc: "jump to screen",
        action: Global::Jump,
    },
    Binding {
        chords: &[k(KeyCode::Char('?'))],
        label: "?",
        desc: "this help",
        action: Global::Help,
    },
    Binding {
        chords: &[ctrl(KeyCode::Char('l'))],
        label: "Ctrl-L",
        desc: "toggle operational log",
        action: Global::Log,
    },
    Binding {
        chords: &[k(KeyCode::Esc)],
        label: "Esc",
        desc: "back / dismiss",
        action: Global::Back,
    },
    Binding {
        chords: &[k(KeyCode::Char('q'))],
        label: "q",
        desc: "quit",
        action: Global::Quit,
    },
];

/// Resolve a key event against [`GLOBAL`]. Linear over seven entries, once per
/// keypress: a lookup table would be more code than the scan it replaces.
pub fn global_for(key: &KeyEvent) -> Option<Global> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    GLOBAL
        .iter()
        .find(|b| {
            b.chords
                .iter()
                .any(|c| c.ctrl == ctrl && c.code == key.code)
        })
        .map(|b| b.action)
}

// ---------------------------------------------------------------------------
// Operational log
// ---------------------------------------------------------------------------

/// Lines kept in the operational log pane. Bounded because a chatty capture can
/// emit for hours and the pane is a debugging aid, not evidence.
const LOG_CAP: usize = 1000;

/// A `tracing` writer that keeps the last [`LOG_CAP`] lines in memory for the
/// log pane. Distinct from the evidence log, which lives in the container and is
/// never written here.
#[derive(Clone, Default)]
pub struct LogBuf(Arc<Mutex<VecDeque<String>>>);

impl LogBuf {
    /// The most recent `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().skip(q.len().saturating_sub(n)).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for line in String::from_utf8_lossy(buf).lines() {
            if !line.trim().is_empty() {
                q.push_back(line.to_string());
            }
        }
        while q.len() > LOG_CAP {
            q.pop_front();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// Route `tracing` into the log pane instead of the terminal, which from here on
/// belongs to the alternate screen.
///
/// Timestamps are omitted: the pane is narrow and this is the operational log.
/// The timestamps that matter forensically are in the container's custody log.
pub fn install_log() -> LogBuf {
    use tracing_subscriber::{fmt, EnvFilter};

    let buf = LogBuf::default();
    let filter = EnvFilter::try_from_env("ARACHNID_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .without_time()
        .with_writer(buf.clone())
        .init();
    buf
}

// ---------------------------------------------------------------------------
// Persisted state
// ---------------------------------------------------------------------------

/// What the TUI remembers between runs. Convenience only: nothing here is
/// evidence, and losing the file costs the operator two path retypes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Saved {
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub last_container: Option<String>,
    #[serde(default)]
    pub recent_pcaps: Vec<String>,
    #[serde(default)]
    pub recent_containers: Vec<String>,
    #[serde(default)]
    pub last_verify: Option<String>,
}

const RECENTS: usize = 8;

impl Saved {
    fn path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state"))
            })?;
        Some(base.join("arachnid").join("tui-state.json"))
    }

    fn load() -> Self {
        let mut s: Self = Self::path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if s.operator.is_empty() {
            s.operator = default_operator();
        }
        s
    }

    /// Best-effort. A UI convenience file is never worth failing a run over, so
    /// a write error becomes a log line and nothing else.
    fn save(&self) {
        let Some(path) = Self::path() else { return };
        let ok = path
            .parent()
            .map(std::fs::create_dir_all)
            .transpose()
            .and_then(|_| serde_json::to_vec_pretty(self).map_err(Into::into))
            .and_then(|b| std::fs::write(&path, b));
        if let Err(e) = ok {
            tracing::debug!(error = %e, path = %path.display(), "could not save TUI state");
        }
    }

    fn remember(list: &mut Vec<String>, value: &str) {
        list.retain(|v| v != value);
        list.insert(0, value.to_string());
        list.truncate(RECENTS);
    }
}

/// Same rule the CLI uses, so a container collected from either front end
/// records the operator the same way.
pub fn default_operator() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    format!("{user}@{}", std::env::consts::OS)
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// What the splash-time probes found. Failures are banner material, never a
/// reason to refuse to start: an unprivileged operator can still verify and
/// report on a container collected elsewhere.
#[derive(Debug, Default)]
pub struct InitReport {
    pub privilege: String,
    pub elevated: bool,
    pub devices: Vec<netcap::DeviceInfo>,
    pub capture_error: Option<String>,
    pub warnings: Vec<String>,
}

/// A capture running in the background. Held on [`App`] rather than in the
/// Capture screen's state so it survives the operator navigating away, which is
/// the whole point of running it on its own thread.
pub struct Running {
    pub stop: Arc<AtomicBool>,
    pub progress: Arc<netcap::Progress>,
    pub started: Instant,
    pub device: String,
    pub output: PathBuf,
}

/// A blocking job the operator started. One at a time: two concurrent runs would
/// mean two containers with interleaved custody timestamps.
pub struct Job {
    pub label: &'static str,
    pub started: Instant,
}

pub enum Msg {
    Init(Box<InitReport>),
    /// A collector is about to run, by name from `arachnid_collect::COLLECTORS`.
    CollectStep(String),
    CollectDone(Box<Result<screens::collect::Done, String>>),
    CaptureDone(Box<Result<screens::capture::Done, String>>),
    ParseDone(Box<Result<screens::parse::Done, String>>),
    ExportDone(Result<String, String>),
    VerifyDone(Box<Result<screens::verify::Done, String>>),
    ReportDone(Box<Result<screens::report::Done, String>>),
    CustodyDone(Box<Result<screens::custody::Done, String>>),
    Toast(String, bool),
}

pub struct Toast {
    pub text: String,
    pub error: bool,
    pub at: Instant,
}

/// A pending yes/no. Every session-affecting action goes through one; nothing
/// that starts, replaces or stops evidence collection happens on a single key.
pub struct Confirm {
    pub prompt: String,
    pub action: Action,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    StopCapture,
    StartCollect,
    StartCapture,
    Export,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub screen: AppScreen,
    /// Where `Esc` returns from a drill-down such as Custody.
    pub back_to: AppScreen,
    pub quit: bool,
    pub show_log: bool,
    pub show_help: bool,
    /// True while a text field has the keyboard; global bindings stand down so
    /// a path containing `q` can actually be typed.
    pub editing: bool,
    pub confirm: Option<Confirm>,
    pub toast: Option<Toast>,
    pub banner_dismissed: bool,
    pub frame: u64,

    pub log: LogBuf,
    pub log_scroll: u16,
    pub saved: Saved,
    pub init: Option<InitReport>,
    pub busy: Option<Job>,
    pub capture: Option<Running>,

    pub tx: Sender<Msg>,
    rx: Receiver<Msg>,

    pub dashboard: screens::dashboard::State,
    pub collect: screens::collect::State,
    pub capture_ui: screens::capture::State,
    pub parse: screens::parse::State,
    pub verify: screens::verify::State,
    pub report: screens::report::State,
    pub custody: screens::custody::State,
}

impl App {
    pub fn new(log: LogBuf) -> Self {
        let (tx, rx) = mpsc::channel();
        let saved = Saved::load();
        App {
            screen: AppScreen::Splash,
            back_to: AppScreen::Dashboard,
            quit: false,
            show_log: false,
            show_help: false,
            editing: false,
            confirm: None,
            toast: None,
            banner_dismissed: false,
            frame: 0,
            log,
            log_scroll: 0,
            init: None,
            busy: None,
            capture: None,
            tx,
            rx,
            dashboard: Default::default(),
            collect: screens::collect::State::new(&saved),
            capture_ui: screens::capture::State::new(&saved),
            parse: screens::parse::State::new(&saved),
            verify: screens::verify::State::new(&saved),
            report: screens::report::State::new(&saved),
            custody: Default::default(),
            saved,
        }
    }

    /// Probe the host while the splash is up. Everything here is read-only and
    /// none of it can fail the launch.
    pub fn start_init(&mut self) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let mut r = InitReport::default();
            (r.privilege, r.elevated) = privilege();
            if !r.elevated {
                r.warnings.push(
                    "not running elevated: collection will miss processes owned by other users, \
                     and live capture will not open a device"
                        .into(),
                );
            }
            match netcap::list_devices() {
                Ok(d) if d.is_empty() => {
                    r.warnings.push(
                        "no capture devices visible (needs root/CAP_NET_RAW on Linux, Npcap on \
                         Windows); capture is unavailable"
                            .into(),
                    );
                    r.devices = d;
                }
                Ok(d) => r.devices = d,
                Err(e) => {
                    let e = format!("{e:#}");
                    r.warnings
                        .push(format!("packet capture library unavailable: {e}"));
                    r.capture_error = Some(e);
                }
            }
            tracing::info!(privilege = %r.privilege, devices = r.devices.len(), "initialized");
            let _ = tx.send(Msg::Init(Box::new(r)));
        });
    }

    pub fn leave_splash(&mut self) {
        if self.screen == AppScreen::Splash {
            self.screen = AppScreen::Dashboard;
        }
    }

    /// Anything that would be lost by quitting now.
    pub fn work_in_flight(&self) -> Option<String> {
        if self.capture.is_some() {
            return Some("a packet capture is running".into());
        }
        self.busy
            .as_ref()
            .map(|j| format!("{} is running", j.label))
    }

    pub fn toast(&mut self, text: impl Into<String>, error: bool) {
        let text = text.into();
        if error {
            tracing::error!("{text}");
        }
        self.toast = Some(Toast {
            text,
            error,
            at: Instant::now(),
        });
    }

    /// Claim the single job slot, or explain why not.
    pub fn begin(&mut self, label: &'static str) -> bool {
        if let Some(j) = &self.busy {
            let running = j.label;
            self.toast(format!("{running} is still running"), true);
            return false;
        }
        self.busy = Some(Job {
            label,
            started: Instant::now(),
        });
        true
    }

    pub fn remember_pcap(&mut self, p: &Path) {
        Saved::remember(&mut self.saved.recent_pcaps, &p.display().to_string());
        self.saved.save();
    }

    pub fn remember_container(&mut self, p: &Path) {
        let s = p.display().to_string();
        Saved::remember(&mut self.saved.recent_containers, &s);
        self.saved.last_container = Some(s);
        self.saved.save();
    }

    pub fn goto(&mut self, screen: AppScreen) {
        if self.screen == screen {
            return;
        }
        self.back_to = self.screen;
        self.screen = screen;
        // Field focus does not survive a screen change; carrying an edit across
        // screens would send keystrokes somewhere the operator is not looking.
        self.editing = false;
    }

    fn cycle(&mut self, forward: bool) {
        let here = TABS.iter().position(|&s| s == self.screen).unwrap_or(0);
        let next = if forward {
            (here + 1) % TABS.len()
        } else {
            (here + TABS.len() - 1) % TABS.len()
        };
        self.goto(TABS[next]);
    }

    // -- events -------------------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent) {
        // Overlays are modal, in the order they can appear on top of each other.
        if self.confirm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let c = self.confirm.take().expect("checked above");
                    self.run_action(c.action);
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.confirm = None;
                }
                _ => {}
            }
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }

        // A field with the keyboard sees everything except the way out.
        if self.editing {
            if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                self.editing = false;
                return;
            }
            screens::on_key(self, key);
            return;
        }

        if screens::on_key(self, key) {
            return;
        }

        let Some(action) = global_for(&key) else {
            return;
        };
        match action {
            Global::Next => self.cycle(true),
            Global::Prev => self.cycle(false),
            Global::Jump => {
                if let KeyCode::Char(c) = key.code {
                    // `global_for` already restricted this to '1'..='6'.
                    let i = (c as u8 - b'1') as usize;
                    self.goto(TABS[i]);
                }
            }
            Global::Help => self.show_help = true,
            Global::Log => {
                self.show_log = !self.show_log;
                self.log_scroll = 0;
            }
            Global::Back => {
                if self.toast.is_some() {
                    self.toast = None;
                } else if self.screen == AppScreen::Custody {
                    let back = self.back_to;
                    self.goto(back);
                } else if self.screen != AppScreen::Dashboard {
                    self.goto(AppScreen::Dashboard);
                }
            }
            Global::Quit => match self.work_in_flight() {
                Some(what) => self.ask(format!("{what}. Quit and lose it?"), Action::Quit),
                None => self.quit = true,
            },
        }
    }

    pub fn ask(&mut self, prompt: impl Into<String>, action: Action) {
        self.confirm = Some(Confirm {
            prompt: prompt.into(),
            action,
        });
    }

    fn run_action(&mut self, action: Action) {
        match action {
            Action::Quit => {
                if let Some(c) = &self.capture {
                    // Set the flag rather than dropping the thread: the savefile
                    // is flushed and its digest reaches the custody log. Losing a
                    // capture to an abrupt exit is losing evidence.
                    c.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                self.quit = true;
            }
            Action::StopCapture => screens::capture::stop(self),
            Action::StartCollect => screens::collect::start(self),
            Action::StartCapture => screens::capture::start(self),
            Action::Export => screens::parse::export(self),
        }
    }

    // -- background messages ------------------------------------------------

    pub fn drain(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(msg) => self.handle(msg),
                Err(TryRecvError::Empty) => break,
                // The sender is cloned onto App, so this cannot happen while the
                // app lives; treat it as "nothing more" rather than panicking.
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Init(r) => {
                self.capture_ui.adopt_devices(&r.devices);
                self.init = Some(*r);
            }
            Msg::CollectStep(name) => self.collect.step(&name),
            Msg::CollectDone(r) => {
                self.busy = None;
                screens::collect::finished(self, *r);
            }
            Msg::CaptureDone(r) => {
                self.capture = None;
                screens::capture::finished(self, *r);
            }
            Msg::ParseDone(r) => {
                self.busy = None;
                screens::parse::finished(self, *r);
            }
            Msg::ExportDone(r) => {
                self.busy = None;
                match r {
                    Ok(path) => {
                        self.remember_container(Path::new(&path));
                        self.toast(format!("exported to {path}"), false);
                    }
                    Err(e) => self.toast(e, true),
                }
            }
            Msg::VerifyDone(r) => {
                self.busy = None;
                screens::verify::finished(self, *r);
            }
            Msg::ReportDone(r) => {
                self.busy = None;
                screens::report::finished(self, *r);
            }
            Msg::CustodyDone(r) => {
                self.busy = None;
                screens::custody::finished(self, *r);
            }
            Msg::Toast(text, error) => self.toast(text, error),
        }
    }

    pub fn tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        // Toasts clear themselves; an error the operator has read should not sit
        // over the screen forever, and Esc dismisses one early.
        if self
            .toast
            .as_ref()
            .is_some_and(|t| t.at.elapsed().as_secs() >= 6)
        {
            self.toast = None;
        }
    }

    /// Frame of the two-cell spinner, for anything in progress.
    pub fn spinner(&self) -> char {
        const FRAMES: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
        FRAMES[(self.frame / 2) as usize % FRAMES.len()]
    }
}

// ---------------------------------------------------------------------------
// Privilege
// ---------------------------------------------------------------------------

/// Effective privilege, for the dashboard card.
///
/// Read from `/proc/self/status`: the effective uid is one integer, and pulling
/// in a libc dependency to read it would cost more than the file does.
#[cfg(target_os = "linux")]
fn privilege() -> (String, bool) {
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                // Uid: <real> <effective> <saved> <fs>
                .and_then(|l| l.split_whitespace().nth(2)?.parse::<u32>().ok())
        });
    match euid {
        Some(0) => ("root".into(), true),
        Some(u) => (format!("uid {u} — unprivileged"), false),
        None => ("unknown".into(), false),
    }
}

#[cfg(windows)]
fn privilege() -> (String, bool) {
    // The one-call form of the CheckTokenMembership dance. A status card needs
    // the yes/no, not the token.
    let admin = unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() };
    if admin {
        ("Administrator".into(), true)
    } else {
        ("standard user — not elevated".into(), false)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn privilege() -> (String, bool) {
    ("unknown on this platform".into(), false)
}

// ---------------------------------------------------------------------------
// Text input
// ---------------------------------------------------------------------------

/// A single-line text field. Append, backspace, clear — enough for a path, a BPF
/// filter and an operator name, which is every field the TUI has.
#[derive(Debug, Default, Clone)]
pub struct Input {
    pub value: String,
}

impl Input {
    pub fn new(value: impl Into<String>) -> Self {
        Input {
            value: value.into(),
        }
    }

    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
    }

    pub fn trimmed(&self) -> &str {
        self.value.trim()
    }

    /// Returns true when the key was consumed.
    pub fn key(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.value.clear();
                true
            }
            KeyCode::Char(c) => {
                self.value.push(c);
                true
            }
            KeyCode::Backspace => {
                self.value.pop();
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every label the help overlay prints must resolve back to the action it
    /// claims. This is the check that keeps the overlay honest.
    #[test]
    fn every_advertised_binding_dispatches() {
        for b in GLOBAL {
            assert!(!b.chords.is_empty(), "{} has no keys", b.label);
            for c in b.chords {
                let mods = if c.ctrl {
                    KeyModifiers::CONTROL
                } else {
                    KeyModifiers::NONE
                };
                let ev = KeyEvent::new(c.code, mods);
                assert_eq!(
                    global_for(&ev),
                    Some(b.action),
                    "{} does not dispatch to its own action",
                    b.label
                );
            }
        }
    }

    /// `Jump` indexes [`TABS`] by subtracting `'1'`, so its keys and the tab
    /// list have to stay the same length.
    #[test]
    fn jump_covers_exactly_the_tabs() {
        let jump = GLOBAL
            .iter()
            .find(|b| b.action == Global::Jump)
            .expect("a jump binding");
        assert_eq!(jump.chords.len(), TABS.len());
    }

    #[test]
    fn input_edits() {
        let mut i = Input::default();
        for c in "/tmp/x".chars() {
            i.key(&KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        i.key(&KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(i.trimmed(), "/tmp/");
        i.key(&KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(i.trimmed(), "");
    }
}
