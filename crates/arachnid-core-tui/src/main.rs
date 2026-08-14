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
