//! Report generation.
//!
//! The JSON report is the contract: schema-versioned, documented in
//! `schema/report.schema.json`, and consumed downstream by the Arachnid Recover
//! module. The Markdown and HTML renderings are for a human skimming the run and
//! carry no information the JSON lacks.

use std::fmt::Write as _;

use anyhow::Result;
