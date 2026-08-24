use std::process::ExitCode;

fn main() -> ExitCode {
    arachnid_recover_cli::run_from(std::env::args_os())
}
