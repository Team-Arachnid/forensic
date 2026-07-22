//! Report generation.
//!
//! The JSON report is the contract: schema-versioned, documented in
//! `schema/report.schema.json`, and consumed downstream by the Arachnid Recover
//! module. The Markdown and HTML renderings are for a human skimming the run and
//! carry no information the JSON lacks.

use std::fmt::Write as _;

use anyhow::Result;
use arachnid_collect::{Collection, MemoryAcquisition};
use arachnid_evidence::Manifest;
use arachnid_netcap::{CaptureStats, PcapAnalysis};
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to [`Report`]. Consumers must reject a
/// major version they do not know.
pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub manifest: Manifest,
    /// Present for a `collect` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<Collection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryAcquisition>,
    /// Present for a `capture` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureStats>,
    /// Present for a `parse-pcap` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap: Option<PcapAnalysis>,
    /// `name` -> SHA-256, mirroring the custody log for quick reference. The
    /// custody log remains the authority; this is a convenience view.
    pub artifacts: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub name: String,
    pub sha256: String,
}

impl Report {
    pub fn new(manifest: Manifest) -> Self {
        Report {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            manifest,
            collection: None,
            memory: None,
            capture: None,
            pcap: None,
            artifacts: Vec::new(),
        }
    }

    pub fn artifact(&mut self, name: &str, sha256: String) {
        if !sha256.is_empty() {
            self.artifacts.push(ArtifactRef {
                name: name.into(),
                sha256,
            });
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}
