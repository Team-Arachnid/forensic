//! Parse PCAP: read a savefile, then optionally export the analysis into an
//! evidence container.
//!
//! Split in two on purpose. `arachnid-core parse-pcap` always writes a
//! container; here the analysis is read-only until the operator exports, so a
//! savefile can be looked at without minting a container for every glance. The
//! export path is the CLI's, unchanged.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use arachnid_evidence::Container;
use arachnid_netcap as netcap;
use arachnid_report::{seal_into, Report};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Action, App, Input, Msg, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "field / row"),
    ("Enter", "edit / analyse"),
    ("h/l", "flows / indicators"),
    ("e", "export to container"),
];

/// pcap, filter, output dir, operator, signing key.
const FIELDS: usize = 5;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Form,
    Results,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Pane {
    Flows,
    Indicators,
}

pub struct State {
    pub input: Input,
    pub filter: Input,
    pub output: Input,
    pub operator: Input,
    pub signing_key: Input,
    pub focus: usize,
    /// Selection over `recent`, offered under the path field.
    pub recent: Vec<String>,
    pub recent_sel: usize,
    pub mode: Mode,
    pub pane: Pane,
    pub row: usize,
    pub analysis: Option<netcap::PcapAnalysis>,
}

pub struct Done {
    pub analysis: netcap::PcapAnalysis,
    pub source: PathBuf,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            input: Input::default(),
            filter: Input::default(),
            output: Input::default(),
            operator: Input::new(saved.operator.clone()),
            signing_key: Input::default(),
            focus: 0,
            recent: saved.recent_pcaps.clone(),
            recent_sel: 0,
            mode: Mode::Form,
            pane: Pane::Flows,
            row: 0,
            analysis: None,
        }
    }

    fn rows(&self) -> usize {
        match (&self.analysis, self.pane) {
            (Some(a), Pane::Flows) => a.flows.len(),
            (Some(a), Pane::Indicators) => a.indicators.len(),
            (None, _) => 0,
        }
    }
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if app.editing {
        let s = &mut app.parse;
        return match s.focus {
            0 => s.input.key(&key),
            1 => s.filter.key(&key),
            2 => s.output.key(&key),
            3 => s.operator.key(&key),
            4 => s.signing_key.key(&key),
            _ => false,
        };
    }

    if app.parse.mode == Mode::Results {
        return results_key(app, key);
    }

    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::wrap(&mut app.parse.focus, 1, FIELDS),
        KeyCode::Char('k') | KeyCode::Up => super::wrap(&mut app.parse.focus, -1, FIELDS),
        // The recent list only makes sense while the path field has focus.
        KeyCode::Char('l') | KeyCode::Right if app.parse.focus == 0 => {
            let n = app.parse.recent.len();
            super::step(&mut app.parse.recent_sel, 1, n);
            adopt_recent(app);
        }
        KeyCode::Char('h') | KeyCode::Left if app.parse.focus == 0 => {
            let n = app.parse.recent.len();
            super::step(&mut app.parse.recent_sel, -1, n);
            adopt_recent(app);
        }
        KeyCode::Enter => app.editing = true,
        KeyCode::Char('a') => analyse(app),
        KeyCode::Char('e') => request_export(app),
        _ => return false,
    }
    true
}

fn adopt_recent(app: &mut App) {
    if let Some(p) = app.parse.recent.get(app.parse.recent_sel).cloned() {
        app.parse.input.set(p);
    }
}

fn results_key(app: &mut App, key: KeyEvent) -> bool {
    let rows = app.parse.rows();
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::step(&mut app.parse.row, 1, rows),
        KeyCode::Char('k') | KeyCode::Up => super::step(&mut app.parse.row, -1, rows),
        KeyCode::Char('h') | KeyCode::Left => {
            app.parse.pane = Pane::Flows;
            app.parse.row = 0;
        }
        KeyCode::Char('l') | KeyCode::Right => {
            app.parse.pane = Pane::Indicators;
            app.parse.row = 0;
        }
        KeyCode::Esc => {
            app.parse.mode = Mode::Form;
        }
        KeyCode::Char('e') => request_export(app),
        _ => return false,
    }
    true
}

fn analyse(app: &mut App) {
    let path = PathBuf::from(app.parse.input.trimmed());
    if path.as_os_str().is_empty() {
        app.toast("a PCAP path is required", true);
        return;
    }
    let filter = match app.parse.filter.trimmed() {
        "" => None,
        f => Some(f.to_string()),
    };
    if !app.begin("PCAP analysis") {
        return;
    }
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = read(&path, filter).map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::ParseDone(Box::new(r)));
    });
}

fn read(path: &Path, filter: Option<String>) -> Result<Done> {
    if !path.is_file() {
        bail!("{} is not a readable file", path.display());
    }
    tracing::info!(input = %path.display(), "parsing savefile");
    let analysis = netcap::parse_pcap(
        path,
        &netcap::ParseOptions {
            max_stream_bytes: netcap::DEFAULT_MAX_STREAM_BYTES,
            filter,
        },
    )?;
    tracing::info!(
        packets = analysis.packets,
        flows = analysis.flows.len(),
        indicators = analysis.indicators.len(),
        "parse finished"
    );
    Ok(Done {
        analysis,
        source: path.to_path_buf(),
    })
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            app.remember_pcap(&done.source);
            app.toast(
                format!(
                    "{} packets, {} flows, {} indicators",
                    done.analysis.packets,
                    done.analysis.flows.len(),
                    done.analysis.indicators.len()
                ),
                false,
            );
            app.parse.analysis = Some(done.analysis);
            app.parse.mode = Mode::Results;
            app.parse.row = 0;
        }
        Err(e) => app.toast(e, true),
    }
}

fn request_export(app: &mut App) {
    if app.parse.analysis.is_none() {
        app.toast("analyse a savefile first (Enter on the path, then a)", true);
        return;
    }
    let out = app.parse.output.trimmed().to_string();
    if out.is_empty() {
        app.toast("output directory is required to export", true);
        return;
    }
    app.ask(
        format!("Write this analysis to a new evidence container at {out}?"),
        Action::Export,
    );
}

/// The container half of `arachnid-core parse-pcap`, on the analysis already in
/// hand. The source file's digest is taken now, at export time, so the container
/// binds the bytes as they are when the evidence is minted.
pub fn export(app: &mut App) {
    let Some(analysis) = app.parse.analysis.clone() else {
        return;
    };
    let out = PathBuf::from(app.parse.output.trimmed());
    let source = PathBuf::from(app.parse.input.trimmed());
    let operator = match app.parse.operator.trimmed() {
        "" => crate::app::default_operator(),
        o => o.to_string(),
    };
    let signing_key = match app.parse.signing_key.trimmed() {
        "" => None,
        k => Some(PathBuf::from(k)),
    };
    if !app.begin("export") {
        return;
    }
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let r = write_container(&out, &source, analysis, &operator, signing_key.as_deref())
            .map(|p| p.display().to_string())
            .map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::ExportDone(r));
    });
}

fn write_container(
    out: &Path,
    source: &Path,
    mut analysis: netcap::PcapAnalysis,
    operator: &str,
    signing_key: Option<&Path>,
) -> Result<PathBuf> {
    let key = signing_key
        .map(arachnid_evidence::load_signing_key)
        .transpose()?;
    let mut container = Container::create(out, operator, key, false)?;
    container.note(format!(
        "invocation: arachnid-tui parse-pcap {} --output {}",
        source.display(),
        out.display()
    ))?;

    // The source file is evidence in its own right; bind its digest to this
    // analysis even though the file stays where it is.
    let (source_hash, size) = arachnid_evidence::sha256_file(source)?;
    container.note(format!(
        "source pcap {} sha256={source_hash} size={size}",
        source.display()
    ))?;
    analysis.source_sha256 = Some(source_hash);

    let mut report = Report::new(container.manifest().clone());
    report.artifact(
        "pcap_analysis.json",
        container.add_json("pcap_analysis.json", &analysis)?,
    );
    report.pcap = Some(analysis);
    seal_into(&mut container, &report).context("seal report into container")?;
    let root = container.root().to_path_buf();
    container.finish()?;
    Ok(root)
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.parse.mode {
        Mode::Form => form(frame, area, app),
        Mode::Results => results(frame, area, app),
    }
}

fn form(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.parse;
    let [fields, recent, hint] = Layout::vertical([
        Constraint::Length(FIELDS as u16),
        Constraint::Min(2),
        Constraint::Length(2),
    ])
    .areas(area);

    let rows: [Rect; 5] = Layout::vertical([Constraint::Length(1); 5]).areas(fields);
    ui::field(
        frame,
        rows[0],
        "pcap file",
        &s.input.value,
        s.focus == 0,
        app.editing && s.focus == 0,
    );
    ui::field(
        frame,
        rows[1],
        "BPF filter",
        &s.filter.value,
        s.focus == 1,
        app.editing && s.focus == 1,
    );
    ui::field(
        frame,
        rows[2],
        "output dir",
        &s.output.value,
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

    let t = Theme::get();
    let mut lines = vec![Line::from(ui::dim(
        " recent savefiles  (h/l on the path field)",
    ))];
    if s.recent.is_empty() {
        lines.push(Line::from(ui::dim("   none yet")));
    }
    for (i, p) in s.recent.iter().enumerate() {
        let selected = s.focus == 0 && i == s.recent_sel;
        lines.push(Line::from(Span::styled(
            format!("   {} {}", if selected { ">" } else { " " }, p),
            if selected { t.selected() } else { t.dimmed() },
        )));
    }
    frame.render_widget(Paragraph::new(lines), recent);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(ui::dim(
                " a  analyse (read-only — the savefile is opened for reading and nothing is written)",
            )),
            Line::from(ui::dim(
                " e  export the analysis to a new evidence container",
            )),
        ]),
        hint,
    );
}

fn results(frame: &mut Frame, area: Rect, app: &App) {
    let t = Theme::get();
    let s = &app.parse;
    let Some(a) = &s.analysis else { return };

    let [head, body] = Layout::vertical([Constraint::Length(2), Constraint::Min(3)]).areas(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                ui::dim(" source  "),
                Span::raw(ui::ellipsis(
                    &a.source,
                    (area.width as usize).saturating_sub(10),
                )),
            ]),
            Line::from(vec![
                ui::dim(" "),
                Span::raw(format!(
                    "{} packets · {} flows · {} indicators · {} decode errors",
                    a.packets,
                    a.flows.len(),
                    a.indicators.len(),
                    a.decode_errors
                )),
                ui::dim("   Esc back to the form"),
            ]),
        ]),
        head,
    );

    // Side by side while both tables can hold their columns; stacked below that.
    let split = body.width >= 120;
    let (left, right) = if split {
        let [l, r] = Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(body);
        (l, Some(r))
    } else {
        (body, None)
    };

    match (right, s.pane) {
        (Some(r), _) => {
            flows(frame, left, app, s.pane == Pane::Flows);
            indicators(frame, r, app, s.pane == Pane::Indicators);
        }
        (None, Pane::Flows) => flows(frame, left, app, true),
        (None, Pane::Indicators) => indicators(frame, left, app, true),
    }
    let _ = t;
}

fn flows(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let t = Theme::get();
    let a = app
        .parse
        .analysis
        .as_ref()
        .expect("results mode has analysis");
    let w = area.width as usize;
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" reconstructed flows ({})", a.flows.len()),
            if focused { t.selected() } else { t.dimmed() },
        )),
        Line::from(ui::dim(format!(
            "  {:<21}{:<21}{:<5}{:>8}{:>10}",
            "source", "destination", "prot", "packets", "stream"
        ))),
    ];
    let rows = area.height.saturating_sub(2) as usize;
    let start = window(app.parse.row, rows, a.flows.len(), focused);
    for (i, f) in a.flows.iter().enumerate().skip(start).take(rows) {
        let selected = focused && i == app.parse.row;
        let text = format!(
            "  {:<21}{:<21}{:<5}{:>8}{:>10}",
            ui::ellipsis(&format!("{}:{}", f.src_addr, f.src_port), 20),
            ui::ellipsis(&format!("{}:{}", f.dst_addr, f.dst_port), 20),
            f.protocol,
            f.packets,
            f.reassembled_bytes
        );
        lines.push(Line::from(Span::styled(
            ui::ellipsis(&text, w),
            if selected {
                t.selected()
            } else {
                ratatui::style::Style::new()
            },
        )));
    }
    more(&mut lines, start + rows, a.flows.len());
    frame.render_widget(Paragraph::new(lines), area);
}

fn indicators(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let t = Theme::get();
    let a = app
        .parse
        .analysis
        .as_ref()
        .expect("results mode has analysis");
    let w = area.width as usize;
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" extracted indicators ({})", a.indicators.len()),
            if focused { t.selected() } else { t.dimmed() },
        )),
        Line::from(ui::dim(format!(
            "  {:<9}{:<34}{:>6}  {}",
            "kind", "value", "count", "first seen"
        ))),
    ];
    let rows = area.height.saturating_sub(2) as usize;
    let start = window(app.parse.row, rows, a.indicators.len(), focused);
    for (i, ind) in a.indicators.iter().enumerate().skip(start).take(rows) {
        let selected = focused && i == app.parse.row;
        let text = format!(
            "  {:<9}{:<34}{:>6}  {}",
            ui::ellipsis(&ind.kind, 8),
            ui::ellipsis(&ind.value, 33),
            ind.count,
            ind.first_seen_utc
        );
        lines.push(Line::from(Span::styled(
            ui::ellipsis(&text, w),
            if selected {
                t.selected()
            } else {
                ratatui::style::Style::new()
            },
        )));
    }
    more(&mut lines, start + rows, a.indicators.len());
    frame.render_widget(Paragraph::new(lines), area);
}

/// Keep the selected row on screen without scrolling an unfocused table.
fn window(sel: usize, rows: usize, len: usize, focused: bool) -> usize {
    if !focused || rows == 0 || len <= rows {
        return 0;
    }
    sel.saturating_sub(rows - 1).min(len - rows)
}

/// Truncated tables say so. A table that silently ends is a table an analyst
/// will read as complete.
fn more(lines: &mut Vec<Line>, shown: usize, len: usize) {
    if shown < len {
        lines.push(Line::from(ui::dim(format!("  … {} more", len - shown))));
    }
}
