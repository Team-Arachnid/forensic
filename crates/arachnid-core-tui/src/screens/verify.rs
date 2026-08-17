//! Verify: re-hash a container's artifacts and check them against its signed
//! custody log.
//!
//! Every verdict on this screen comes from `arachnid_evidence::verify`. The TUI
//! does not re-hash anything itself: a second implementation of verification is
//! exactly what a forensic tool must not have, because then a bug in one could
//! make a broken container look clean in the other.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use arachnid_evidence::{Manifest, VerifyReport};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, AppScreen, Input, Msg, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "row"),
    ("h/l", "recent container"),
    ("Enter", "edit path"),
    ("v", "verify"),
    ("c", "chain of custody"),
];

pub struct State {
    pub container: Input,
    pub recent: Vec<String>,
    pub recent_sel: usize,
    pub row: usize,
    pub done: Option<Done>,
}

pub struct Done {
    pub report: VerifyReport,
    pub manifest: Manifest,
    pub verified_utc: String,
    pub root: PathBuf,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            container: Input::new(saved.last_container.clone().unwrap_or_default()),
            recent: saved.recent_containers.clone(),
            recent_sel: 0,
            row: 0,
            done: None,
        }
    }
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        return app.verify.container.key(&key);
    }
    let rows = app
        .verify
        .done
        .as_ref()
        .map_or(0, |d| d.report.artifacts.len());
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.verify.row, 1, rows),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.verify.row, -1, rows),
        KeyCode::Char('l') | KeyCode::Right => {
            let n = app.verify.recent.len();
            super::step(&mut app.verify.recent_sel, 1, n);
            adopt_recent(app);
        }
        KeyCode::Char('h') | KeyCode::Left => {
            let n = app.verify.recent.len();
            super::step(&mut app.verify.recent_sel, -1, n);
            adopt_recent(app);
        }
        KeyCode::Enter => app.editing = true,
        KeyCode::Char('v') => start(app),
        KeyCode::Char('c') => {
            let path = PathBuf::from(app.verify.container.trimmed());
            super::custody::open(app, path, AppScreen::Verify);
        }
        _ => return false,
    }
    true
}

fn adopt_recent(app: &mut App) {
    if let Some(p) = app.verify.recent.get(app.verify.recent_sel).cloned() {
        app.verify.container.set(p);
    }
}

fn start(app: &mut App) {
    let root = PathBuf::from(app.verify.container.trimmed());
    if root.as_os_str().is_empty() {
        app.toast("a container path is required", true);
        return;
    }
    if !app.begin("verification") {
        return;
    }
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = run(&root).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::VerifyDone(Box::new(r)));
    });
}

fn run(root: &Path) -> Result<Done> {
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).with_context(|| {
            format!("read {} (is this an Arachnid container?)", root.display())
        })?)
        .context("parse manifest.json")?;
    let report =
        arachnid_evidence::verify(root).with_context(|| format!("verify {}", root.display()))?;
    Ok(Done {
        report,
        manifest,
        verified_utc: arachnid_evidence::now_utc(),
        root: root.to_path_buf(),
    })
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            app.remember_container(&done.root);
            let ok = done.report.ok();
            app.saved.last_verify = Some(if ok {
                format!("verified {} artifacts", done.report.artifacts_checked)
            } else {
                format!("FAILED: {} problem(s)", done.report.problems.len())
            });
            app.toast(
                if ok {
                    "VERIFIED: every artifact matches the signed custody log".into()
                } else {
                    format!("FAILED: {} problem(s)", done.report.problems.len())
                },
                !ok,
            );
            app.verify.row = 0;
            app.verify.done = Some(done);
        }
        Err(e) => app.toast(e, true),
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.verify;

    let [path_row, recent, summary, table] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(if s.done.is_some() { 1 } else { 6 }),
        Constraint::Length(if s.done.is_some() { 7 } else { 2 }),
        Constraint::Min(3),
    ])
    .areas(area);

    ui::field(
        frame,
        path_row,
        "container",
        &s.container.value,
        true,
        app.editing,
    );

    if s.done.is_none() {
        let mut lines = vec![Line::from(ui::dim(" recent containers  (h/l)"))];
        if s.recent.is_empty() {
            lines.push(Line::from(ui::dim("   none yet")));
        }
        for (i, p) in s.recent.iter().take(4).enumerate() {
            let selected = i == s.recent_sel;
            lines.push(Line::from(Span::styled(
                format!("   {} {}", if selected { ">" } else { " " }, p),
                if selected { t.selected() } else { t.dimmed() },
            )));
        }
        frame.render_widget(Paragraph::new(lines), recent);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(ui::dim(
                    " v  verify — re-reads and re-hashes every artifact",
                )),
                Line::from(ui::dim(" c  inspect the chain-of-custody log")),
            ]),
            summary,
        );
        return;
    }

    let d = s.done.as_ref().expect("checked above");
    let r = &d.report;
    let ok = r.ok();
    frame.render_widget(
        Paragraph::new(Line::from(ui::dim(
            " c  chain of custody   ·   v  verify again",
        ))),
        recent,
    );

    let mut head = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", if ok { "VERIFIED" } else { "FAILED" }),
                t.verdict(ok),
            ),
            Span::raw(if ok {
                "every artifact matches the signed custody log".to_string()
            } else {
                format!("{} problem(s)", r.problems.len())
            }),
        ]),
        Line::from(vec![
            ui::dim(" key fingerprint  "),
            Span::raw(r.key_fingerprint.clone()),
        ]),
        Line::from(ui::dim(
            " this confirms internal consistency; it proves origin only against a fingerprint recorded at collection",
        )),
        Line::from(vec![
            ui::dim(" collected  "),
            Span::raw(d.manifest.created_utc.clone()),
            ui::dim("    verified  "),
            Span::raw(d.verified_utc.clone()),
        ]),
        Line::from(vec![
            ui::dim(" schema  "),
            Span::raw(r.schema_version.clone()),
            ui::dim("    custody records  "),
            Span::raw(format!("{}", r.records)),
            ui::dim("    hashed  "),
            Span::raw(format!("{}", r.artifacts_checked)),
        ]),
    ];
    for p in r.problems.iter().take(2) {
        head.push(Line::from(Span::styled(
            format!(" ! {p}"),
            t.verdict(false),
        )));
    }
    if r.problems.len() > 2 {
        head.push(Line::from(ui::dim(format!(
            " … {} more problem(s), one per row below",
            r.problems.len() - 2
        ))));
    }
    frame.render_widget(Paragraph::new(head), summary);

    // -- per-artifact table
    let w = table.width as usize;
    let mut lines = vec![Line::from(ui::dim(format!(
        "  {:<6}{:<24}{:>12}  {:<64}",
        "state", "artifact", "size", "sha256 as logged"
    )))];
    let rows = table.height.saturating_sub(1) as usize;
    let start = window(s.row, rows, r.artifacts.len());
    for (i, a) in r.artifacts.iter().enumerate().skip(start).take(rows) {
        let text = format!(
            "  {:<6}{:<24}{:>12}  {}",
            ui::mark(a.ok),
            ui::ellipsis(&a.name, 23),
            a.size.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            a.sha256.clone().unwrap_or_else(|| "(none recorded)".into())
        );
        let mut style = t.verdict(a.ok);
        if i == s.row {
            style = style.patch(t.selected());
        }
        lines.push(Line::from(Span::styled(ui::ellipsis(&text, w), style)));
    }
    if start + rows < r.artifacts.len() {
        lines.push(Line::from(ui::dim(format!(
            "  … {} more",
            r.artifacts.len() - start - rows
        ))));
    }
    if let Some(note) = r.artifacts.get(s.row).and_then(|a| a.note.as_ref()) {
        lines.push(Line::from(Span::styled(
            format!("  {note}"),
            Style::new().fg(t.bad),
        )));
    }
    frame.render_widget(Paragraph::new(lines), table);
}

fn window(sel: usize, rows: usize, len: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    sel.saturating_sub(rows - 1).min(len - rows)
}
