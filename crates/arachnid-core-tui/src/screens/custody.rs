//! Chain of custody: every record in the log, in order, in full.
//!
//! Nothing here is summarized or elided. Trust in a forensic UI depends on the
//! raw log being reachable, so the table shows every entry and the panel under
//! it shows the selected record's fields complete — full digest, not a prefix.
//!
//! Records are read with `arachnid_evidence::read_log`, which does not check
//! signatures or the hash chain. That is Verify's job, and this screen says so
//! rather than implying the log has been validated by being displayed.

use std::path::PathBuf;

use arachnid_evidence::Record;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, AppScreen, Msg};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[("j/k", "record"), ("g/G", "first / last"), ("Esc", "back")];

#[derive(Default)]
pub struct State {
    pub root: PathBuf,
    pub records: Vec<Record>,
    pub row: usize,
}

pub struct Done {
    pub root: PathBuf,
    pub records: Vec<Record>,
}

/// Load a container's log and show it. `back` is where `Esc` returns to, so the
/// screen can be reached from both Verify and Report without either knowing
/// about the other.
pub fn open(app: &mut App, root: PathBuf, back: AppScreen) {
    if root.as_os_str().is_empty() {
        app.toast("a container path is required", true);
        return;
    }
    if !app.begin("custody log read") {
        return;
    }
    app.goto(AppScreen::Custody);
    app.back_to = back;
    app.custody.records.clear();
    app.custody.root = root.clone();
    app.custody.row = 0;

    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = arachnid_evidence::read_log(&root)
            .map(|records| Done { root, records })
            .map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::CustodyDone(Box::new(r)));
    });
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            app.custody.root = done.root;
            app.custody.records = done.records;
            app.custody.row = 0;
        }
        Err(e) => {
            let back = app.back_to;
            app.goto(back);
            app.toast(e, true);
        }
    }
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    let n = app.custody.records.len();
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.custody.row, 1, n),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.custody.row, -1, n),
        KeyCode::Char('g') => app.custody.row = 0,
        KeyCode::Char('G') => app.custody.row = n.saturating_sub(1),
        _ => return false,
    }
    true
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();
    let s = &app.custody;

    let [head, table, detail] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(9),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                ui::dim(" container  "),
                Span::raw(s.root.display().to_string()),
                ui::dim("   records  "),
                Span::raw(format!("{}", s.records.len())),
            ]),
            Line::from(ui::dim(
                " shown as written. Signatures and the hash chain are not checked here — that is Verify.",
            )),
        ]),
        head,
    );

    if s.records.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(ui::dim(if app.busy.is_some() {
                " reading…"
            } else {
                " no records"
            }))),
            table,
        );
        return;
    }

    let w = table.width as usize;
    let mut lines = vec![Line::from(ui::dim(format!(
        "  {:<5}{:<26}{:<11}{:<22}{}",
        "seq", "timestamp (UTC)", "event", "name", "sha256"
    )))];
    let rows = table.height.saturating_sub(1) as usize;
    let start = if rows == 0 || s.records.len() <= rows {
        0
    } else {
        s.row.saturating_sub(rows - 1).min(s.records.len() - rows)
    };
    for (i, r) in s.records.iter().enumerate().skip(start).take(rows) {
        let text = format!(
            "  {:<5}{:<26}{:<11}{:<22}{}",
            r.seq,
            r.ts_utc,
            ui::ellipsis(&r.event, 10),
            ui::ellipsis(r.name.as_deref().unwrap_or("-"), 21),
            r.sha256.as_deref().unwrap_or("-")
        );
        lines.push(Line::from(Span::styled(
            ui::ellipsis(&text, w),
            if i == s.row {
                t.selected()
            } else {
                ratatui::style::Style::new()
            },
        )));
    }
    frame.render_widget(Paragraph::new(lines), table);

    // The selected record, complete. The table truncates to fit; this does not.
    let Some(r) = s.records.get(s.row) else {
        return;
    };
    let detail_lines = vec![
        Line::from(Span::styled(format!(" record {}", r.seq), t.selected())),
        Line::from(vec![
            ui::dim(" timestamp  "),
            Span::raw(r.ts_utc.clone()),
            ui::dim("   +"),
            Span::raw(format!("{} ns since run start", r.mono_ns)),
        ]),
        Line::from(vec![
            ui::dim(" operator   "),
            Span::raw(r.operator.clone()),
            ui::dim("   event  "),
            Span::raw(r.event.clone()),
        ]),
        Line::from(vec![
            ui::dim(" artifact   "),
            Span::raw(r.name.clone().unwrap_or_else(|| "-".into())),
            ui::dim("   size  "),
            Span::raw(r.size.map(|s| s.to_string()).unwrap_or_else(|| "-".into())),
        ]),
        Line::from(vec![
            ui::dim(" sha256     "),
            Span::raw(r.sha256.clone().unwrap_or_else(|| "-".into())),
        ]),
        Line::from(vec![ui::dim(" prev       "), Span::raw(r.prev.clone())]),
        Line::from(vec![
            ui::dim(" detail     "),
            Span::raw(r.detail.clone().unwrap_or_else(|| "-".into())),
        ]),
    ];
    frame.render_widget(Paragraph::new(detail_lines), detail);
}
