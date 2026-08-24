//! Thin wrapper. The command lives in the library beside this file so the
//! unified `arachnid-cli` front end can call it directly.

use std::process::ExitCode;

fn main() -> ExitCode {
    arachnid_sanitize_cli::run_from(std::env::args_os())
}
