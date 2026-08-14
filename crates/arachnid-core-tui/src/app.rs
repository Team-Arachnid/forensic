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
