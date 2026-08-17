//! Report: what a container holds, and re-rendering its summary.
//!
//! The container already carries `report.json`, `report.md` and `report.html`,
//! all three sealed at collection. Exporting here re-renders from the JSON — the
//! same thing `arachnid-core report` does — so a copy can be dropped somewhere
//! outside the container without touching the container itself.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use arachnid_report::{to_html, to_markdown, Report};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, AppScreen, Input, Msg, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "field"),
    ("Enter", "edit / cycle"),
    ("o", "open container"),
    ("x", "export"),
    ("c", "chain of custody"),
];

/// container, export path, format.
const FIELDS: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Html,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Markdown => "markdown",
            Format::Html => "html",
        }
    }

    fn next(self) -> Self {
        match self {
            Format::Json => Format::Markdown,
            Format::Markdown => Format::Html,
            Format::Html => Format::Json,
        }
    }

    fn render(self, r: &Report) -> Result<String> {
        Ok(match self {
            Format::Json => String::from_utf8(r.to_json()?)?,
            Format::Markdown => to_markdown(r),
            Format::Html => to_html(r),
        })
    }
}

pub struct State {
    pub container: Input,
    pub export_to: Input,
    pub format: Format,
    pub focus: usize,
    pub loaded: Option<Done>,
}

pub struct Done {
    pub report: Report,
    pub custody_records: usize,
    pub root: PathBuf,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            container: Input::new(saved.last_container.clone().unwrap_or_default()),
            export_to: Input::default(),
            format: Format::Markdown,
            focus: 0,
            loaded: None,
        }
    }
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        let s = &mut app.report;
        return match s.focus {
            0 => s.container.key(&key),
            1 => s.export_to.key(&key),
            _ => false,
        };
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::wrap(&mut app.report.focus, 1, FIELDS),
        KeyCode::Char('k') | KeyCode::Up => super::wrap(&mut app.report.focus, -1, FIELDS),
        KeyCode::Enter => match app.report.focus {
            2 => app.report.format = app.report.format.next(),
            _ => app.editing = true,
        },
        KeyCode::Char('o') => load(app),
        KeyCode::Char('x') => export(app),
        KeyCode::Char('c') => {
            let path = PathBuf::from(app.report.container.trimmed());
            super::custody::open(app, path, AppScreen::Report);
        }
        _ => return false,
    }
    true
}

fn load(app: &mut App) {
    let root = PathBuf::from(app.report.container.trimmed());
    if root.as_os_str().is_empty() {
        app.toast("a container path is required", true);
        return;
    }
    if !app.begin("report load") {
        return;
    }
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = read(&root).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::ReportDone(Box::new(r)));
    });
}

fn read(root: &Path) -> Result<Done> {
    let path = root.join("artifacts/report.json");
    let raw = std::fs::read(&path)
        .with_context(|| format!("read {} (is this an Arachnid container?)", path.display()))?;
    let report: Report = serde_json::from_slice(&raw).context("parse report.json")?;
    if report.schema_version.split('.').next() != Some("1") {
        bail!(
            "report schema {} is not supported by this build (expected 1.x)",
            report.schema_version
        );
    }
    // Counted, not rendered, here: the log itself has its own screen, and a
    // number on this one must not be mistaken for having seen it.
    let custody_records = arachnid_evidence::read_log(root)?.len();
    Ok(Done {
        report,
        custody_records,
        root: root.to_path_buf(),
    })
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            app.remember_container(&done.root);
            app.toast(format!("loaded {}", done.root.display()), false);
            app.report.loaded = Some(done);
        }
        Err(e) => app.toast(e, true),
    }
}

fn export(app: &mut App) {
    let Some(loaded) = &app.report.loaded else {
        app.toast("open a container first (o)", true);
        return;
    };
    let to = app.report.export_to.trimmed();
    if to.is_empty() {
        app.toast("an export path is required", true);
        return;
    }
    let format = app.report.format;
    // Rendering is in-memory and fast enough that a thread would only add a way
    // for the result to arrive after the operator has moved on.
    match format
        .render(&loaded.report)
        .and_then(|s| std::fs::write(to, s).map_err(Into::into))
    {
        Ok(()) => {
            tracing::info!(path = to, format = format.name(), "report written");
            app.toast(format!("wrote {} as {}", to, format.name()), false);
        }
        Err(e) => app.toast(format!("{e:#}"), true),
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.report;

    let [fields, hint, body] = Layout::vertical([
        Constraint::Length(FIELDS as u16),
        Constraint::Length(2),
        Constraint::Min(3),
    ])
    .areas(area);

    let rows: [Rect; 3] = Layout::vertical([Constraint::Length(1); 3]).areas(fields);
    ui::field(
        frame,
        rows[0],
        "container",
        &s.container.value,
        s.focus == 0,
        app.editing && s.focus == 0,
    );
    ui::field(
        frame,
        rows[1],
        "export to",
        &s.export_to.value,
        s.focus == 1,
        app.editing && s.focus == 1,
    );
    ui::field(
        frame,
        rows[2],
        "format",
        s.format.name(),
        s.focus == 2,
        false,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(ui::dim(
                " o  open   ·   x  export a copy   ·   c  chain of custody",
            )),
            Line::from(ui::dim(
                " the container already holds all three renderings, sealed; this writes a copy elsewhere",
            )),
        ]),
        hint,
    );

    let Some(d) = &s.loaded else {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(" no container open."))),
            body,
        );
        return;
    };

    let r = &d.report;
    let m = &r.manifest;
    let mut lines = vec![
        Line::from(vec![
            ui::dim(" container id  "),
            Span::raw(m.container_id.clone()),
        ]),
        Line::from(vec![
            ui::dim(" collected     "),
            Span::raw(m.created_utc.clone()),
            ui::dim("  by  "),
            Span::raw(m.operator.clone()),
            ui::dim("  on  "),
            Span::raw(format!("{} ({})", m.host, m.platform)),
        ]),
        Line::from(vec![
            ui::dim(" tool          "),
            Span::raw(format!("{} {}", m.tool, m.tool_version)),
            ui::dim("   schema  "),
            Span::raw(r.schema_version.clone()),
        ]),
        Line::raw(""),
        Line::from(Span::styled(" artifacts", t.selected())),
    ];
    for a in &r.artifacts {
        lines.push(Line::from(vec![
            Span::raw(format!("   {:<24}", ui::ellipsis(&a.name, 23))),
            ui::dim(a.sha256.clone()),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(" contents", t.selected())));
    let mut counts: Vec<(&str, usize)> = Vec::new();
    if let Some(c) = &r.collection {
        counts.extend([
            ("processes", c.processes.len()),
            ("connections", c.connections.len()),
            ("sessions", c.sessions.len()),
            ("kernel modules", c.kernel_modules.len()),
            ("persistence", c.persistence.len()),
            ("collector warnings", c.warnings.len()),
        ]);
    }
    if let Some(c) = &r.capture {
        counts.extend([
            ("captured packets", c.packets_written as usize),
            (
                "dropped packets",
                (c.packets_dropped_kernel + c.packets_dropped_interface) as usize,
            ),
        ]);
    }
    if let Some(p) = &r.pcap {
        counts.extend([
            ("pcap packets", p.packets as usize),
            ("flows", p.flows.len()),
            ("indicators", p.indicators.len()),
            ("decode errors", p.decode_errors as usize),
        ]);
    }
    if r.memory.is_some() {
        counts.push(("memory images", 1));
    }
    counts.push(("chain-of-custody entries", d.custody_records));

    let max = counts.iter().map(|(_, n)| *n as u64).max().unwrap_or(0);
    for (name, n) in counts {
        lines.push(Line::from(vec![
            Span::raw(format!("   {name:<26}{n:>9}  ")),
            ui::dim(ui::bar(n as u64, max, 20)),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), body);
}
