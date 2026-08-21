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
        const SCREENS: [AppScreen; 9] = [
            AppScreen::Splash,
            AppScreen::Dashboard,
            AppScreen::Collect,
            AppScreen::Capture,
            AppScreen::Parse,
            AppScreen::Verify,
            AppScreen::Report,
            AppScreen::Sanitize,
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

    /// Sanitize is a state machine of sub-views, and each one has its own
    /// layout. Rendering only its default view would leave the other four
    /// untested, and a layout that panics takes the terminal with it.
    #[test]
    fn every_sanitize_sub_view_renders_at_every_supported_size() {
        use screens::sanitize::View;

        const VIEWS: [View; 5] = [
            View::Devices,
            View::Method,
            View::Confirm,
            View::Progress,
            View::Result,
        ];

        for (w, h) in [(80, 24), (32, 8), (200, 60), (60, 16)] {
            for view in VIEWS {
                let mut app = App::new(app::LogBuf::default());
                app.screen = AppScreen::Sanitize;
                app.sanitize.view = view;
                // A device present, so the views that describe one have
                // something to draw rather than bailing to the list.
                app.sanitize.devices = vec![arachnid_sanitize_core::Device {
                    path: "/dev/sdz".into(),
                    model: "TEST DISK".into(),
                    serial: "TEST-0001".into(),
                    size_bytes: 512 * 1024 * 1024,
                    bus: arachnid_sanitize_core::BusType::Sata,
                    removable: true,
                    is_system: true,
                    system_reason: Some("test fixture".into()),
                }];
                let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("test backend");
                terminal
                    .draw(|frame| ui::render(frame, &mut app))
                    .unwrap_or_else(|e| panic!("Sanitize/{view:?} at {w}x{h}: {e}"));
            }
        }
    }

    /// The confirm view must not be clearable by the reflexes that clear the
    /// ordinary y/n dialog, and must not accept the commit key before the
    /// cooldown has elapsed.
    #[test]
    fn the_wipe_confirm_resists_muscle_memory() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use screens::sanitize::View;

        let mut app = App::new(app::LogBuf::default());
        app.screen = AppScreen::Sanitize;
        app.sanitize.devices = vec![arachnid_sanitize_core::Device {
            path: "/dev/sdz".into(),
            model: "TEST DISK".into(),
            serial: "TEST-0001".into(),
            size_bytes: 512 * 1024 * 1024,
            bus: arachnid_sanitize_core::BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        }];
        app.sanitize.view = View::Confirm;
        app.sanitize.confirm_since = Some(Instant::now());
        app.sanitize.serial.set("TEST-0001");
        app.sanitize.dry_run = false;

        // y and Enter are what the ordinary confirm takes. Neither may start a
        // wipe from here.
        for code in [KeyCode::Char('y'), KeyCode::Enter] {
            app.editing = false;
            app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
            assert!(
                app.sanitize_job.is_none(),
                "{code:?} started a wipe from the confirm view"
            );
        }

        // The commit key itself is refused while the countdown is running.
        app.editing = false;
        app.on_key(KeyEvent::new(KeyCode::Char('W'), KeyModifiers::SHIFT));
        assert!(
            app.sanitize_job.is_none(),
            "the commit key was accepted before the cooldown elapsed"
        );
    }

    /// A wipe in flight is the one job whose loss cannot be undone, so quitting
    /// must ask, and must tell the wipe to stop rather than dropping it.
    #[test]
    fn quitting_mid_wipe_asks_first() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut app = App::new(app::LogBuf::default());
        app.screen = AppScreen::Dashboard;
        app.sanitize_job = Some(app::SanitizeJob {
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            progress: std::sync::Arc::new(arachnid_sanitize_core::engine::Progress::default()),
            started: Instant::now(),
            device: "/dev/sdz".into(),
            method: "NIST SP 800-88 Clear",
            dry_run: false,
        });

        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.quit, "quit without confirming during a wipe");
        assert!(app.confirm.is_some(), "no confirmation was raised");

        app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(app.quit);
        assert!(
            app.sanitize_job
                .as_ref()
                .expect("wipe handle")
                .cancel
                .load(std::sync::atomic::Ordering::Relaxed),
            "quit did not ask the wipe to stop"
        );
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
