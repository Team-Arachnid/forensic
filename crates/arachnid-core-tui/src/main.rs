//! Arachnid Core TUI — the operator-facing front end for Arachnid Core.
//!
//! Part of the Arachnid Forensic suite. For use by authorized analysts on
//! systems they have permission to examine.
//!
//! This is a view/controller layer over the same library crates the CLI drives:
//! `arachnid-collect`, `arachnid-netcap`, `arachnid-evidence`,
//! `arachnid-report`. It never shells out to `arachnid-core`, and it can do
//! nothing the CLI cannot already do. Anything it shows was computed by the
//! engine, not re-derived here.
//!
//! Threading: every engine call is blocking and synchronous, so long-running
//! work goes on a plain `std::thread` and reports back over an `mpsc` channel
//! that the render loop drains each tick. The UI thread never blocks on the
//! engine.

mod app;
mod screens;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyEventKind};

use app::{App, AppScreen};

/// Render cadence. Fast enough that a spinner looks alive and a keypress lands
/// immediately; slow enough that an idle TUI costs nothing.
const TICK: Duration = Duration::from_millis(60);

/// The splash is a courtesy, not a gate. It holds the screen for at least this
/// long so the animation is not a flicker...
const SPLASH_MIN: Duration = Duration::from_millis(900);
/// ...and never for longer than this, whether or not initialization has
/// finished. A tool that makes an operator wait to see a warning has buried it.
const SPLASH_MAX: Duration = Duration::from_millis(1600);

fn main() -> io::Result<()> {
    // The operational log has to be captured before anything can emit into it,
    // and it must never reach the terminal directly: stdout and stderr belong to
    // the alternate screen from here on.
    let log = app::install_log();

    // `ratatui::init` installs a panic hook that leaves raw mode and the
    // alternate screen before the panic prints, so a crash cannot hand the
    // operator a broken shell. It is the only reason this is not hand-rolled.
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, log);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, log: app::LogBuf) -> io::Result<()> {
    let mut app = App::new(log);
    app.start_init();
    let started = Instant::now();

    while !app.quit {
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        // One poll per tick keeps input latency at the tick and leaves the CPU
        // alone in between. Background work arrives on the channel, not here.
        if event::poll(TICK)? {
            match event::read()? {
                // Windows reports both press and release; acting on both would
                // double every keystroke.
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if app.screen == AppScreen::Splash {
                        if started.elapsed() >= SPLASH_MIN {
                            app.leave_splash();
                        }
                    } else {
                        app.on_key(key);
                    }
                }
                Event::Resize(..) => {}
                _ => {}
            }
        }

        app.drain();
        app.tick();

        // Leave as soon as initialization is done, but never before the minimum
        // and never after the maximum — a slow privilege or device probe must
        // not hold the dashboard hostage; its findings arrive as a banner.
        let elapsed = started.elapsed();
        if app.screen == AppScreen::Splash
            && (elapsed >= SPLASH_MAX || (app.init.is_some() && elapsed >= SPLASH_MIN))
        {
            app.leave_splash();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Every screen, at the smallest supported terminal and at a comfortable
    /// one. A layout that panics takes the terminal with it, so this is the
    /// check that has to exist: it fails if any screen cannot draw itself.
    #[test]
    fn every_screen_renders_at_every_supported_size() {
        const SCREENS: [AppScreen; 8] = [
            AppScreen::Splash,
            AppScreen::Dashboard,
            AppScreen::Collect,
            AppScreen::Capture,
            AppScreen::Parse,
            AppScreen::Verify,
            AppScreen::Report,
            AppScreen::Custody,
        ];

        for (w, h) in [(80, 24), (32, 8), (200, 60), (60, 16)] {
            for screen in SCREENS {
                for overlay in [0u8, 1, 2, 3] {
                    let mut app = App::new(app::LogBuf::default());
                    app.screen = screen;
                    app.show_help = overlay & 1 != 0;
                    app.show_log = overlay & 2 != 0;
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("test backend");
                    terminal
                        .draw(|frame| ui::render(frame, &mut app))
                        .unwrap_or_else(|e| panic!("{screen:?} at {w}x{h}: {e}"));
                }
            }
        }
    }

    /// The splash has to actually say what this is; a blank one is a hang that
    /// looks like a splash.
    #[test]
    fn splash_names_the_tool() {
        let mut app = App::new(app::LogBuf::default());
        // Far enough in that the progressive reveal has drawn every row.
        app.frame = 64;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            text.contains("ARACHNID"),
            "splash did not draw the wordmark"
        );
    }

    /// A confirmation must stand between the operator and anything that starts,
    /// replaces or stops evidence collection.
    #[test]
    fn quitting_mid_capture_asks_first() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut app = App::new(app::LogBuf::default());
        app.screen = AppScreen::Dashboard;
        app.capture = Some(app::Running {
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            progress: std::sync::Arc::new(arachnid_netcap::Progress::default()),
            started: Instant::now(),
            device: "lo".into(),
            output: std::path::PathBuf::from("/tmp/x"),
        });

        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.quit, "quit without confirming during a capture");
        assert!(app.confirm.is_some(), "no confirmation was raised");

        app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(app.quit);
        let stopping = app
            .capture
            .as_ref()
            .expect("capture handle")
            .stop
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(stopping, "quit did not ask the capture to flush and seal");
    }
}
