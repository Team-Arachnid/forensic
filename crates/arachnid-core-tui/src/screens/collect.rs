//! Collect: run every volatile-state collector into a new evidence container.
//!
//! The collectors, their order and their results come from
//! `arachnid_collect::collect_all_with_progress`. This screen only draws what
//! that reports; it never runs a collector of its own.

use std::path::PathBuf;

use anyhow::{Context, Result};
use arachnid_collect as collect;
use arachnid_evidence::Container;
use arachnid_report::{seal_into, Report};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Action, App, Input, Msg, Saved};
use crate::ui::{self, Theme};

pub const KEYS: &[(&str, &str)] = &[
    ("j/k", "field"),
    ("Enter", "edit / toggle"),
    ("r", "run collection"),
];

/// output, operator, signing key, hash-binaries.
const FIELDS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Pending,
    Running,
    Done,
}

pub struct State {
    pub output: Input,
    pub operator: Input,
    pub signing_key: Input,
    pub hash_binaries: bool,
    pub focus: usize,
    /// One entry per `collect::COLLECTORS`, in the order they run.
    pub steps: Vec<(&'static str, Step)>,
    pub done: Option<Done>,
}

pub struct Done {
    pub root: PathBuf,
    pub fingerprint: String,
    pub counts: Vec<(&'static str, usize)>,
    pub warnings: Vec<String>,
}

impl State {
    pub fn new(saved: &Saved) -> Self {
        State {
            output: Input::default(),
            operator: Input::new(saved.operator.clone()),
            signing_key: Input::default(),
            hash_binaries: true,
            focus: 0,
            steps: fresh_steps(),
            done: None,
        }
    }

    /// A collector is about to run. Everything before it in the list has to be
    /// finished, which is what makes this a checklist rather than a spinner.
    pub fn step(&mut self, name: &str) {
        for (n, s) in self.steps.iter_mut() {
            if *n == name {
                *s = Step::Running;
                break;
            }
            *s = Step::Done;
        }
    }
}

fn fresh_steps() -> Vec<(&'static str, Step)> {
    collect::COLLECTORS
        .iter()
        .map(|n| (*n, Step::Pending))
        .collect()
}

pub fn on_key(app: &mut App, key: KeyEvent) -> bool {
    let s = &mut app.collect;
    if app.editing {
        return match s.focus {
            0 => s.output.key(&key),
            1 => s.operator.key(&key),
            2 => s.signing_key.key(&key),
            _ => false,
        };
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => super::wrap(&mut s.focus, 1, FIELDS),
        KeyCode::Char('k') | KeyCode::Up => super::wrap(&mut s.focus, -1, FIELDS),
        KeyCode::Enter => match s.focus {
            3 => s.hash_binaries = !s.hash_binaries,
            _ => app.editing = true,
        },
        KeyCode::Char('r') => {
            let out = app.collect.output.trimmed().to_string();
            if out.is_empty() {
                app.toast("output directory is required", true);
            } else {
                app.ask(
                    format!("Create a new evidence container at {out} and collect?"),
                    Action::StartCollect,
                );
            }
        }
        _ => return false,
    }
    true
}

pub fn start(app: &mut App) {
    let out = PathBuf::from(app.collect.output.trimmed());
    let operator = match app.collect.operator.trimmed() {
        "" => crate::app::default_operator(),
        o => o.to_string(),
    };
    let key = match app.collect.signing_key.trimmed() {
        "" => None,
        k => Some(PathBuf::from(k)),
    };
    let hash_binaries = app.collect.hash_binaries;
    if !app.begin("collection") {
        return;
    }
    app.collect.steps = fresh_steps();
    app.collect.done = None;

    let tx = app.tx.clone();
    let steps_tx = tx.clone();
    std::thread::spawn(move || {
        let r = run(
            &out,
            &operator,
            key.as_deref(),
            hash_binaries,
            &mut |name| {
                let _ = steps_tx.send(Msg::CollectStep(name.to_string()));
            },
        )
        .map_err(|e| format!("{e:#}"));
        let _ = tx.send(Msg::CollectDone(Box::new(r)));
    });
}

/// The same sequence `arachnid-core collect` performs, through the same
/// library calls. Divergence here would mean two front ends producing
/// containers that are not comparable.
fn run(
    out: &std::path::Path,
    operator: &str,
    signing_key: Option<&std::path::Path>,
    hash_binaries: bool,
    starting: &mut dyn FnMut(&str),
) -> Result<Done> {
    let key = signing_key
        .map(arachnid_evidence::load_signing_key)
        .transpose()?;
    let mut container = Container::create(out, operator, key, false)?;
    // The custody log records what was asked for, as the equivalent CLI
    // invocation, so a reader need not know which front end was used.
    container.note(format!(
        "invocation: arachnid-tui collect --output {}{}",
        out.display(),
        if hash_binaries {
            ""
        } else {
            " --no-hash-binaries"
        }
    ))?;

    let mut report = Report::new(container.manifest().clone());
    tracing::info!("collecting volatile system state");
    let c = collect::collect_all_with_progress(collect::Options { hash_binaries }, starting);

    report.artifact(
        "processes.json",
        container.add_json("processes.json", &c.processes)?,
    );
    report.artifact(
        "connections.json",
        container.add_json("connections.json", &c.connections)?,
    );
    report.artifact(
        "sessions.json",
        container.add_json("sessions.json", &c.sessions)?,
    );
    report.artifact(
        "kernel_modules.json",
        container.add_json("kernel_modules.json", &c.kernel_modules)?,
    );
    report.artifact(
        "persistence.json",
        container.add_json("persistence.json", &c.persistence)?,
    );
    for w in &c.warnings {
        container.note(format!("collector degraded: {w}"))?;
    }

    let counts = vec![
        ("processes", c.processes.len()),
        ("connections", c.connections.len()),
        ("sessions", c.sessions.len()),
        ("kernel_modules", c.kernel_modules.len()),
        ("persistence", c.persistence.len()),
    ];
    let warnings = c.warnings.clone();
    report.collection = Some(c);

    seal_into(&mut container, &report).context("seal report into container")?;
    let fingerprint = container.key_fingerprint();
    let root = container.root().to_path_buf();
    container.finish()?;

    Ok(Done {
        root,
        fingerprint,
        counts,
        warnings,
    })
}

pub fn finished(app: &mut App, result: Result<Done, String>) {
    match result {
        Ok(done) => {
            for (_, s) in app.collect.steps.iter_mut() {
                *s = Step::Done;
            }
            app.remember_container(&done.root);
            let n = done.warnings.len();
            app.toast(
                if n == 0 {
                    format!("collected into {}", done.root.display())
                } else {
                    format!(
                        "collected into {} — {n} collector(s) degraded",
                        done.root.display()
                    )
                },
                false,
            );
            app.collect.done = Some(done);
        }
        Err(e) => {
            app.collect.steps = fresh_steps();
            app.toast(e, true);
        }
    }
}
