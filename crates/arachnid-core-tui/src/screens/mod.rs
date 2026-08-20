//! One module per screen.
//!
//! A screen owns its state, its rendering, its key handling and the key table
//! the help overlay reads. Adding a module — Sanitize, Recover — is a new file
//! here plus a variant in [`AppScreen`]; no existing screen is touched.

pub mod capture;
pub mod collect;
pub mod custody;
pub mod dashboard;
pub mod parse;
pub mod report;
pub mod sanitize;
pub mod verify;

use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::{App, AppScreen};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.screen {
        // Drawn by `ui::render` before the frame chrome exists.
        AppScreen::Splash => {}
        AppScreen::Dashboard => dashboard::render(frame, area, app),
        AppScreen::Collect => collect::render(frame, area, app),
        AppScreen::Capture => capture::render(frame, area, app),
        AppScreen::Parse => parse::render(frame, area, app),
        AppScreen::Verify => verify::render(frame, area, app),
        AppScreen::Report => report::render(frame, area, app),
        AppScreen::Sanitize => sanitize::render(frame, area, app),
        AppScreen::Custody => custody::render(frame, area, app),
    }
}

/// Give the current screen first refusal on a key. `true` means handled, and the
/// global keymap does not see it.
pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    match app.screen {
        AppScreen::Splash => false,
        AppScreen::Dashboard => dashboard::on_key(app, key),
        AppScreen::Collect => collect::on_key(app, key),
        AppScreen::Capture => capture::on_key(app, key),
        AppScreen::Parse => parse::on_key(app, key),
        AppScreen::Verify => verify::on_key(app, key),
        AppScreen::Report => report::on_key(app, key),
        AppScreen::Sanitize => sanitize::on_key(app, key),
        AppScreen::Custody => custody::on_key(app, key),
    }
}

/// Screen-specific bindings, for the help overlay and the footer.
pub fn keys(screen: AppScreen) -> &'static [(&'static str, &'static str)] {
    match screen {
        AppScreen::Splash => &[],
        AppScreen::Dashboard => dashboard::KEYS,
        AppScreen::Collect => collect::KEYS,
        AppScreen::Capture => capture::KEYS,
        AppScreen::Parse => parse::KEYS,
        AppScreen::Verify => verify::KEYS,
        AppScreen::Report => report::KEYS,
        AppScreen::Sanitize => sanitize::KEYS,
        AppScreen::Custody => custody::KEYS,
    }
}

/// Move a selection index by one, without wrapping past the ends — a list that
/// jumps from the last row to the first loses an operator's place.
pub fn step(sel: &mut usize, delta: isize, len: usize) {
    if len == 0 {
        *sel = 0;
        return;
    }
    let next = (*sel as isize + delta).clamp(0, len as isize - 1);
    *sel = next as usize;
}

/// Cycle a focus index, which does wrap: a form is a ring, not a list.
pub fn wrap(focus: &mut usize, delta: isize, len: usize) {
    if len == 0 {
        return;
    }
    *focus = ((*focus as isize + delta).rem_euclid(len as isize)) as usize;
}
