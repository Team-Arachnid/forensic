use std::process::ExitCode;

fn main() -> ExitCode {
    arachnid_cli::run_from(std::env::args_os())
}
