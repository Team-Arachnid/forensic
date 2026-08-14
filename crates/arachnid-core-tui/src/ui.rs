//! Chrome: theme, frame layout, splash, overlays, and the shared widgets the
//! screens draw with.
//!
//! Colour is load-bearing in exactly three places — accent for "you are here",
//! green for verified, red for failed — and nowhere else. Everything the UI says
//! it also says in text, so a monochrome terminal loses styling and no meaning.

use std::sync::OnceLock;

use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, AppScreen, Global, GLOBAL, TABS};
use crate::screens;

pub struct Theme {
    pub accent: Color,
    pub ok: Color,
    pub bad: Color,
    pub warn: Color,
    pub dim: Color,
    pub mono: bool,
}

impl Theme {
    /// `NO_COLOR`, per no-color.org: set and non-empty means no colour, whatever
    /// the value is.
    fn detect() -> Self {
        let mono = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if mono {
            Theme {
                accent: Color::Reset,
                ok: Color::Reset,
                bad: Color::Reset,
                warn: Color::Reset,
                dim: Color::Reset,
                mono: true,
            }
        } else {
            Theme {
                accent: Color::Cyan,
                ok: Color::Green,
                bad: Color::Red,
                warn: Color::Yellow,
                dim: Color::DarkGray,
                mono: false,
            }
        }
    }

    pub fn get() -> &'static Theme {
        static THEME: OnceLock<Theme> = OnceLock::new();
        THEME.get_or_init(Theme::detect)
    }

    /// "This one is selected." Without colour that has to be reverse video —
    /// there is nothing else left that carries the same weight.
    pub fn selected(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
        }
    }

    pub fn dimmed(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new().fg(self.dim)
        }
    }

    /// Verified or failed. The glyph carries the verdict; the colour only
    /// repeats it.
    pub fn verdict(&self, ok: bool) -> Style {
        Style::new().fg(if ok { self.ok } else { self.bad })
    }
}

pub fn mark(ok: bool) -> &'static str {
    if ok {
        "OK"
    } else {
        "FAIL"
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

pub fn render(frame: &mut Frame, app: &mut App) {
    let full = frame.area();
    let t = Theme::get();

    if full.width < 32 || full.height < 8 {
        frame.render_widget(
            Paragraph::new("terminal too small\nneeds 32x8")
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            full,
        );
        return;
    }

    if app.screen == AppScreen::Splash {
        splash(frame, full, app, t);
        return;
    }

    // The log pane is the first thing to go when there is no room for it: it is
    // a debugging aid, and the screen under it is the work.
    let log_h = if app.show_log && full.height >= 18 {
        9
    } else {
        0
    };
    let banner_h = u16::from(banner_text(app).is_some() && full.height >= 12);

    let [header, banner_area, body, log_area, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(banner_h),
        Constraint::Min(3),
        Constraint::Length(log_h),
        Constraint::Length(1),
    ])
    .areas(full);

    tabs(frame, header, app, t);
    if banner_h > 0 {
        const HINT: &str = "  (Esc dismisses)";
        let room = (banner_area.width as usize).saturating_sub(3 + HINT.len());
        let text = ellipsis(&banner_text(app).unwrap_or_default(), room);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ! ", Style::new().fg(t.warn).add_modifier(Modifier::BOLD)),
                Span::raw(text),
                Span::styled(HINT, t.dimmed()),
            ])),
            banner_area,
        );
    }

    screens::render(frame, body, app);

    if log_h > 0 {
        log_pane(frame, log_area, app, t);
    }
    footer_line(frame, footer, app, t);

    if app.show_help {
        help(frame, full, app, t);
    }
    if let Some(c) = &app.confirm {
        confirm(frame, full, &c.prompt, t);
    }
}

fn banner_text(app: &App) -> Option<String> {
    // The Dashboard prints every warning in full; a banner there would only
    // repeat itself.
    if app.banner_dismissed || app.screen == AppScreen::Dashboard {
        return None;
    }
    let w = &app.init.as_ref()?.warnings;
    match w.len() {
        0 => None,
        1 => Some(w[0].clone()),
        n => Some(format!("{} (+{} more, see Dashboard)", w[0], n - 1)),
    }
}

fn tabs(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let here = TABS.iter().position(|&s| s == app.screen);

    // Below 80 columns the full tab strip does not fit, so it collapses to a
    // position indicator rather than being truncated into nonsense.
    if area.width < 80 {
        let label = match here {
            Some(i) => format!(
                " arachnid  {}/{}  {}",
                i + 1,
                TABS.len(),
                app.screen.title()
            ),
            None => format!(" arachnid  {}", app.screen.title()),
        };
        frame.render_widget(Paragraph::new(Span::styled(label, t.selected())), area);
        return;
    }

    let mut spans = vec![Span::styled(" arachnid ", t.dimmed())];
    for (i, tab) in TABS.iter().enumerate() {
        let selected = here == Some(i);
        spans.push(Span::styled(
            format!(" {}:{} ", i + 1, tab.title()),
            if selected { t.selected() } else { t.dimmed() },
        ));
    }
    if here.is_none() {
        spans.push(Span::styled(
            format!("  {} ", app.screen.title()),
            t.selected(),
        ));
    }
    // Work in flight stays visible from every screen; that is the point of
    // running it on its own thread.
    if app.capture.is_some() {
        spans.push(Span::styled(
            "  [capturing]",
            Style::new().fg(t.warn).add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(j) = &app.busy {
        spans.push(Span::styled(
            format!("  [{} {}s]", j.label, j.started.elapsed().as_secs()),
            Style::new().fg(t.warn),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn footer_line(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    if let Some(toast) = &app.toast {
        let style = if toast.error {
            Style::new().fg(t.bad).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(t.ok)
        };
        let tag = if toast.error { " error " } else { " ok " };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(tag, style),
                Span::raw(toast.text.clone()),
            ])),
            area,
        );
        return;
    }

    // Both halves come from the same tables the help overlay reads. The help
    // binding goes first: the footer is the only thing that gets truncated, and
    // the way to the full list must never be what falls off the end.
    let (help, rest): (Vec<_>, Vec<_>) = GLOBAL.iter().partition(|b| b.action == Global::Help);
    let mut parts: Vec<String> = help
        .iter()
        .map(|b| format!("{} {}", b.label, b.desc))
        .collect();
    parts.extend(
        screens::keys(app.screen)
            .iter()
            .map(|(k, d)| format!("{k} {d}")),
    );
    parts.extend(rest.iter().map(|b| format!("{} {}", b.label, b.desc)));
    let line = format!(" {}", parts.join("  ·  "));
    frame.render_widget(Paragraph::new(Span::styled(line, t.dimmed())), area);
}
