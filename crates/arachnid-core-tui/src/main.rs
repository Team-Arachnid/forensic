//! Thin wrapper. The UI lives in the library beside this file so the unified
//! `arachnid-cli` front end can launch it directly.

fn main() -> std::io::Result<()> {
    arachnid_core_tui::start()
}
