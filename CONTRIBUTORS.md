# Contributors

Arachnid Core is built and maintained by the Arachnid team.

| Contributor | GitHub | Area |
| --- | --- | --- |
| Shubham Choudhary | [@ch0udharyji](https://github.com/ch0udharyji) | Project lead — evidence container, collector, report, TUI, `arachnid-cli`, release and install pipeline, CI |
| Divyanshu | [@geekydivyanshu](https://github.com/geekydivyanshu) | Network capture (`arachnid-netcap`) and secure erasure (`arachnid-sanitize-core` / `-cli`) |
| Shristy Paliwal | [@shristypaliwal](https://github.com/shristypaliwal) | Documentation — README, threat model, SOC allowlisting guide and the JSON Schemas |
| Barbie Grover | [@BarbieGrover](https://github.com/BarbieGrover) | Documentation — the project wiki, the Pages site and the usage guide |
| Priyanshu | [@madmaxgodzzz](https://github.com/madmaxgodzzz) | Landing page — sections, copy, responsive layout and WCAG AA accessibility |

## Ownership by area

| Area | Owner |
| --- | --- |
| `crates/arachnid-evidence` | Shubham Choudhary |
| `crates/arachnid-collect` | Shubham Choudhary |
| `crates/arachnid-report` | Shubham Choudhary |
| `crates/arachnid-core-tui`, `crates/arachnid-core-cli` | Shubham Choudhary |
| `crates/arachnid-cli` | Shubham Choudhary |
| `crates/arachnid-recover-core`, `crates/arachnid-recover-cli` | Shubham Choudhary |
| `crates/arachnid-netcap` | Divyanshu |
| `crates/arachnid-sanitize-core`, `crates/arachnid-sanitize-cli` | Divyanshu |
| `README.md`, `THREAT_MODEL.md`, `docs/SOC-ALLOWLISTING.md`, `schema/` | Shristy Paliwal |
| `docs/wiki/`, `docs/_layouts/`, `arachnid-usage-guide.md` | Barbie Grover |
| `landing/` | Priyanshu, with Shubham Choudhary |
| `release/`, `scripts/`, `.github/workflows/` | Shubham Choudhary |

## Contributing

Work happens on branches off `main` and lands through pull requests. Before opening one:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Commits follow Conventional Commits (`feat(netcap): ...`, `docs: ...`, `fix(cli): ...`).
Keep the scope matching the crate you touched, so ownership stays readable in the log.
