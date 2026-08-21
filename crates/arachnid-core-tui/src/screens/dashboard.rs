//! Home: what this host will and will not let the operator do, what session is
//! current, and a way into every other screen.

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, AppScreen};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[("j/k", "move"), ("Enter", "open")];

/// Quick-launch tiles, in the order they appear.
const TILES: [(AppScreen, &str); 6] = [
    (AppScreen::Collect, "collect volatile system state"),
    (AppScreen::Capture, "capture live network traffic"),
    (AppScreen::Parse, "analyse an existing PCAP"),
    (AppScreen::Verify, "verify an evidence container"),
    (AppScreen::Report, "render a container's report"),
    (
        AppScreen::Sanitize,
        "securely erase a device — destroys data",
    ),
];

/// Status cards across the top. Named because three things depend on it — the
/// column split, the width each card ellipsizes to, and the terminal width
/// below which the boxes are dropped — and they must not drift apart.
const CARDS: usize = 4;

/// Columns a boxed card needs to hold its values without wrapping. Below
/// `CARDS * MIN_CARD_W` the cards are listed flat instead.
const MIN_CARD_W: u16 = 33;

#[derive(Default)]
pub struct State {
    pub tile: usize,
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            super::step(&mut app.dashboard.tile, 1, TILES.len());
            true
        }
        KeyCode::Char('k') | KeyCode::Up => {
            super::step(&mut app.dashboard.tile, -1, TILES.len());
            true
        }
        KeyCode::Enter => {
            app.goto(TILES[app.dashboard.tile.min(TILES.len() - 1)].0);
            true
        }
        _ => false,
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let t = Theme::get();

    // Below CARDS * MIN_CARD_W the cards side by side leave no room for their
    // values. Narrow terminals drop the boxes entirely rather than shrink them:
    // borders cost six rows that the content needs more.
    let boxed = area.width >= CARDS as u16 * MIN_CARD_W;
    let cards = status_cards(app, area.width as usize);
    let card_h = if boxed {
        cards.iter().map(|(_, l)| l.len()).max().unwrap_or(1) as u16 + 2
    } else {
        cards.iter().map(|(_, l)| l.len() as u16 + 1).sum()
    };

    let [head, tiles, warns] = Layout::vertical([
        Constraint::Length(card_h),
        Constraint::Length(TILES.len() as u16 + 1),
        Constraint::Min(1),
    ])
    .areas(area);

    if boxed {
        let boxes: [Rect; CARDS] =
            Layout::horizontal([Constraint::Ratio(1, CARDS as u32); CARDS]).areas(head);
        for (slot, (title, lines)) in boxes.into_iter().zip(cards) {
            ui::card(frame, slot, title, lines);
        }
    } else {
        let mut flat = Vec::new();
        for (title, lines) in cards {
            for (i, line) in lines.into_iter().enumerate() {
                let mut spans = vec![Span::styled(
                    format!(" {:<17}", if i == 0 { title } else { "" }),
                    t.dimmed(),
                )];
                spans.extend(line.spans);
                flat.push(Line::from(spans));
            }
        }
        frame.render_widget(Paragraph::new(flat), head);
    }

    // -- quick launch
    let mut lines = vec![Line::from(ui::dim(" go to"))];
    for (i, (screen, desc)) in TILES.iter().enumerate() {
        let selected = i == app.dashboard.tile;
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    " {} {:<12}",
                    if selected { ">" } else { " " },
                    screen.title()
                ),
                if selected { t.selected() } else { t.dimmed() },
            ),
            ui::dim(*desc),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), tiles);

    // -- startup warnings, in full. This is the only place they are not
    //    abbreviated, which is why the banner stands down on this screen.
    let mut wl = Vec::new();
    match &app.init {
        Some(r) if !r.warnings.is_empty() => {
            for w in &r.warnings {
                wl.push(Line::from(vec![
                    Span::styled(" ! ", Style::new().fg(t.warn).add_modifier(Modifier::BOLD)),
                    Span::raw(w.clone()),
                ]));
            }
        }
        Some(_) => wl.push(Line::from(ui::dim(
            " no startup warnings; every check passed",
        ))),
        None => wl.push(Line::from(ui::dim(" checking host…"))),
    }
    frame.render_widget(Paragraph::new(wl).wrap(Wrap { trim: true }), warns);
}

/// The status cards, as (title, body). Built once and then either boxed or
/// listed, so the two layouts can never say different things.
fn status_cards(app: &App, width: usize) -> [(&'static str, Vec<Line<'static>>); CARDS] {
    let t = Theme::get();
    // Columns available inside one card. Derived from the card count rather
    // than hardcoded, so adding the fourth card could not leave the other three
    // ellipsizing to a width that no longer exists.
    let cell = width / CARDS;

    let privilege = match &app.init {
        None => vec![Line::from(ui::dim("checking…"))],
        Some(r) => vec![
            Line::styled(r.privilege.clone(), t.verdict(r.elevated)),
            Line::from(ui::dim(if r.elevated {
                "full collection available"
            } else {
                "collection will be partial"
            })),
        ],
    };

    let capture = match &app.init {
        None => vec![Line::from(ui::dim("checking…"))],
        Some(r) => match (&r.capture_error, r.devices.len()) {
            (Some(e), _) => vec![
                Line::styled("unavailable", t.verdict(false)),
                Line::from(ui::dim(ui::ellipsis(e, cell))),
            ],
            (None, 0) => vec![
                Line::styled("no devices visible", t.verdict(false)),
                Line::from(ui::dim("needs root/CAP_NET_RAW, or Npcap")),
            ],
            (None, n) => vec![
                Line::styled(format!("{n} device(s)"), t.verdict(true)),
                Line::from(ui::dim(ui::ellipsis(
                    &r.devices
                        .iter()
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    cell,
                ))),
            ],
        },
    };

    let mut session = match &app.saved.last_container {
        None => vec![Line::from(ui::dim("no container yet"))],
        Some(c) => vec![Line::raw(ui::ellipsis(c, cell))],
    };
    session.push(Line::from(vec![
        ui::dim("operator "),
        Span::raw(app.saved.operator.clone()),
    ]));
    session.push(match &app.saved.last_verify {
        Some(v) => Line::styled(v.clone(), t.verdict(v.starts_with("verified"))),
        None => Line::from(ui::dim("last verify: none this session")),
    });

    // Sanitize is the one module here that destroys data, so its card states
    // what is running even when that is "nothing" — an operator should never
    // have to open the screen to find out whether a wipe is in flight.
    let sanitize = match &app.sanitize_job {
        Some(j) => {
            let p = &j.progress;
            let pass = p.pass.load(std::sync::atomic::Ordering::Relaxed);
            let passes = p.passes_total.load(std::sync::atomic::Ordering::Relaxed);
            vec![
                Line::styled(
                    if j.dry_run {
                        "dry run in progress".to_string()
                    } else {
                        "1 wipe in progress".to_string()
                    },
                    if j.dry_run {
                        t.verdict(true)
                    } else {
                        Style::new().fg(t.bad).add_modifier(Modifier::BOLD)
                    },
                ),
                Line::from(ui::dim(ui::ellipsis(&j.device, cell))),
                Line::from(ui::dim(format!(
                    "pass {pass}/{passes}  {:.1}%",
                    p.fraction() * 100.0
                ))),
            ]
        }
        None => {
            let devices = app.sanitize.devices.len();
            let system = app.sanitize.devices.iter().filter(|d| d.is_system).count();
            vec![
                Line::from(ui::dim("no wipe running")),
                Line::from(ui::dim(if devices == 0 {
                    "no devices enumerated".to_string()
                } else {
                    format!("{devices} device(s), {system} system-hosting")
                })),
                match &app.sanitize.last {
                    Some(d) => Line::styled(
                        match &d.certificate {
                            Some(_) => "last: certified".to_string(),
                            None => "last: not certified".to_string(),
                        },
                        t.verdict(d.certificate.is_some()),
                    ),
                    None => Line::from(ui::dim("none this session")),
                },
            ]
        }
    };

    [
        ("privilege", privilege),
        ("packet capture", capture),
        ("evidence session", session),
        ("sanitize", sanitize),
    ]
}
