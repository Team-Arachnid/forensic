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
                // Magenta for the spider the suite is named after. It is the
                // one ANSI slot that collides with none of the three verdict
                // colours below, so the accent can never be misread as a
                // verdict — and the terminal's own palette picks the shade.
                accent: Color::Magenta,
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

fn log_pane(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let block = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(t.dimmed())
        .title(Span::styled(
            format!(" operational log — {} lines (Ctrl-L) ", app.log.len()),
            t.dimmed(),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = inner.height as usize;
    let skip = app.log_scroll as usize;
    let mut lines = app.log.tail(rows + skip);
    lines.truncate(lines.len().saturating_sub(skip));
    let start = lines.len().saturating_sub(rows);
    let text: Vec<Line> = lines[start..]
        .iter()
        .map(|l| Line::raw(l.clone()))
        .collect();
    frame.render_widget(Paragraph::new(text), inner);
}

// ---------------------------------------------------------------------------
// Splash
// ---------------------------------------------------------------------------

/// The full mark. Kept as art in its own file rather than as a string literal
/// here, so it can be edited in a drawing tool and dropped back in.
const LOGO: &str = include_str!("logo.txt");
const LOGO_W: u16 = 90;

/// The compact mark, for the terminal sizes operators actually run. Every row
/// is the same width so it centres cleanly.
const ART: [&str; 9] = [
    r"\   \  \   /\   /  /   /",
    r" \   \  \ (oo) /  /   / ",
    r"  \   \__\/__\/__/   /  ",
    r"   \____/ /  \ \____/   ",
    r"    ___/ /(  )\ \___    ",
    r"   /   /  \__/  \   \   ",
    r"  /   /    /\    \   \  ",
    r"        ARACHNID        ",
    r"   F O R E N S I C S    ",
];

const ART_W: u16 = 24;

/// Ticks the mark takes to draw itself. At the 60 ms tick this lands just
/// inside `SPLASH_MIN`, so the reveal finishes before the splash can end —
/// whichever mark is drawing, and however many rows it has.
const REVEAL_TICKS: usize = 14;

/// Rows of `art` revealed so far, padded back to full height so the block does
/// not jump upward as it draws.
fn revealed(art: &[&'static str], frame: u64, style: Style) -> Vec<Line<'static>> {
    let shown = (frame as usize * art.len() / REVEAL_TICKS + 1).min(art.len());
    let mut text: Vec<Line> = art[..shown]
        .iter()
        .map(|l| Line::from(Span::styled(*l, style)))
        .collect();
    text.resize(art.len(), Line::raw(""));
    text
}

fn splash(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let status = match &app.init {
        None => format!("{} checking host…", app.spinner()),
        Some(r) if r.warnings.is_empty() => "ready".into(),
        Some(r) => format!("ready — {} warning(s)", r.warnings.len()),
    };

    // Too narrow or too short for the art: a plain wordmark says the same thing
    // and never wraps into rubble.
    if area.width < ART_W + 4 || area.height < 14 {
        let text = vec![
            Line::from(Span::styled(
                "ARACHNID FORENSICS",
                Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
            )),
            Line::raw("Core — live triage & network forensics"),
            Line::raw(""),
            Line::styled(status, t.dimmed()),
        ];
        frame.render_widget(
            Paragraph::new(text).alignment(Alignment::Center),
            centre(area, 42, 4),
        );
        return;
    }

    // The full mark only when it genuinely fits; the compact one otherwise.
    // Scaling the big art down turns it into noise, so it is shown whole or not
    // at all.
    let logo: Vec<&'static str> = LOGO.lines().collect();
    let big = area.width >= LOGO_W + 2 && area.height >= logo.len() as u16 + 5;
    let (art, w) = if big {
        (logo.as_slice(), LOGO_W)
    } else {
        (&ART[..], ART_W)
    };

    // Progressive reveal, so the mark draws itself while the host is probed.
    let mut text = revealed(art, app.frame, Style::new().fg(t.accent));
    if big {
        // The big art is the spider alone, so it needs the wordmark under it.
        // The compact one already carries its own.
        text.push(Line::raw(""));
        text.push(Line::styled(
            "ARACHNID FORENSICS",
            Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
        ));
    }
    text.push(Line::raw(""));
    text.push(Line::styled(status, t.dimmed()));
    text.push(Line::styled("authorized DFIR use only", t.dimmed()));

    let h = text.len() as u16;
    frame.render_widget(
        Paragraph::new(text).alignment(Alignment::Center),
        centre(area, w + 2, h),
    );
}

// ---------------------------------------------------------------------------
// Overlays
// ---------------------------------------------------------------------------

pub fn centre(area: Rect, w: u16, h: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(h.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::horizontal([Constraint::Length(w.min(area.width))])
        .flex(Flex::Center)
        .areas(row);
    cell
}

fn help(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let mut lines = vec![Line::styled(
        format!("{} — screen keys", app.screen.title()),
        t.selected(),
    )];
    let screen_keys = screens::keys(app.screen);
    if screen_keys.is_empty() {
        lines.push(Line::styled("  (none)", t.dimmed()));
    }
    for (k, d) in screen_keys {
        lines.push(binding_line(k, d, t));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("global", t.selected()));
    for b in GLOBAL {
        lines.push(binding_line(b.label, b.desc, t));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "  lists: j/k or arrows, Enter selects, Esc backs out",
        t.dimmed(),
    ));
    lines.push(Line::styled("  any key closes this", t.dimmed()));

    let h = (lines.len() as u16 + 2).min(area.height);
    popup(
        frame,
        centre(area, 66.min(area.width), h),
        " keybindings ",
        lines,
        t,
    );
}

fn binding_line<'a>(k: &'a str, d: &'a str, t: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {k:<12}"), Style::new().fg(t.accent)),
        Span::raw(d),
    ])
}

fn confirm(frame: &mut Frame, area: Rect, prompt: &str, t: &Theme) {
    let lines = vec![
        Line::raw(prompt.to_string()),
        Line::raw(""),
        Line::from(vec![
            Span::styled("y", Style::new().fg(t.accent).add_modifier(Modifier::BOLD)),
            Span::raw(" confirm    "),
            Span::styled("n", Style::new().fg(t.accent).add_modifier(Modifier::BOLD)),
            Span::raw(" / Esc cancel"),
        ]),
    ];
    // Grow to fit the prompt. A confirmation that clips the path it is asking
    // about is asking the operator to approve something they cannot read.
    let w = 62.min(area.width);
    let inner = (w as usize).saturating_sub(2).max(1);
    let wrapped = prompt.chars().count().div_ceil(inner) as u16;
    let h = (wrapped + 4).min(area.height);
    popup(frame, centre(area, w, h), " confirm ", lines, t);
}

fn popup(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>, t: &Theme) {
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(t.accent))
        .title(Span::styled(title.to_string(), t.selected()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ---------------------------------------------------------------------------
// Shared widgets
// ---------------------------------------------------------------------------

/// A labelled text field. `focused` is where the cursor keys are; `editing` says
/// the keyboard is inside it, which is shown with a block cursor because there
/// is no other way to tell in a monochrome terminal.
pub fn field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    editing: bool,
) {
    let t = Theme::get();
    let marker = if focused { ">" } else { " " };
    let mut spans = vec![
        Span::styled(
            format!("{marker} {label:<14}"),
            if focused { t.selected() } else { t.dimmed() },
        ),
        Span::raw(value.to_string()),
    ];
    if editing {
        spans.push(Span::styled(
            "█",
            Style::new().add_modifier(Modifier::SLOW_BLINK),
        ));
    } else if value.is_empty() {
        spans.push(Span::styled("(empty)", t.dimmed()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A status card: one label, one value, and an optional verdict colour.
pub fn card(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>) {
    let t = Theme::get();
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.dimmed())
        .title(Span::styled(format!(" {title} "), t.dimmed()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

/// A horizontal bar for a count, drawn in text so it survives a monochrome
/// terminal and a terminal without box-drawing glyphs alike.
pub fn bar(count: u64, max: u64, width: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let n = ((count as f64 / max as f64) * width as f64).round() as usize;
    "#".repeat(n.clamp(usize::from(count > 0), width))
}

/// Truncate to `width` columns, marking that something was cut. Tables use this
/// instead of letting a long path push the rest of a row off screen.
pub fn ellipsis(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

/// The dim style as a `Stylize` shorthand for screens that only need the colour.
pub fn dim(s: impl Into<String>) -> Span<'static> {
    Span::raw(s.into()).style(Theme::get().dimmed())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The art has to be rectangular or centring it tears the box apart.
    #[test]
    fn art_is_rectangular() {
        for (i, line) in ART.iter().enumerate() {
            assert_eq!(
                line.chars().count(),
                ART_W as usize,
                "row {i} is {:?}",
                line
            );
        }
    }

    /// Same rule for the file-backed mark, which is the one most likely to be
    /// re-edited in a drawing tool and pasted back ragged.
    #[test]
    fn the_logo_file_is_rectangular() {
        for (i, line) in LOGO.lines().enumerate() {
            assert_eq!(
                line.chars().count(),
                LOGO_W as usize,
                "logo.txt row {i} is {:?}",
                line
            );
        }
    }

    #[test]
    fn ellipsis_marks_what_it_cuts() {
        assert_eq!(ellipsis("abcdef", 6), "abcdef");
        assert_eq!(ellipsis("abcdef", 4), "abc…");
        assert_eq!(ellipsis("", 4), "");
    }

    /// A non-zero count must never render as an empty bar: "some" and "none"
    /// have to look different.
    #[test]
    fn bar_shows_any_nonzero_count() {
        assert_eq!(bar(0, 100, 10), "");
        assert_eq!(bar(1, 100_000, 10).len(), 1);
        assert_eq!(bar(100, 100, 10).len(), 10);
    }
}
