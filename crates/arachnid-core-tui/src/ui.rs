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
