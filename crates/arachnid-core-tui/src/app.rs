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

