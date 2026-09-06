//! Certificates under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.
//!
//! Section 63 replaced Section 65B of the Indian Evidence Act, 1872 on 1 July
//! 2024. It is the route by which a computer output reaches an Indian court
//! without producing the original device, and it works only when a certificate
//! carrying the section's stated particulars accompanies the record — signed,
//! per Section 63(4), by **two different people**: the person responsible for
//! the device, and an independent expert.
//!
//! # What this module is
//!
//! A generator over evidence Arachnid has already collected and signed. It does
//! not collect anything, and it re-states no fact it cannot read out of a
//! container's own custody log. Everything statutory that a machine can know —
//! device identity, timestamps, digests, the custody key — is pulled from
//! [`crate::verify`]; everything a machine cannot know — who the signers are,
//! what the record is, whether the system was operating properly — is supplied
//! by the people who will sign, and is refused rather than guessed.
//!
//! # What this module is not
//!
//! It is not legal advice and it does not make a record admissible. It produces
//! a document with the structure Section 63 describes, populated with facts that
//! verify. Whether a court accepts it is a question for counsel, and
//! [`DISCLAIMER`] says so on the face of every certificate this module emits, in
//! both output formats.
//!
//! The wording of the conditions below tracks the section as published; it is
//! reproduced here as a template for a lawyer to review, not as a settled
//! rendering of the statute. See `docs/wiki/16-Court-Certificates.md`.
//!
//! # Refusals
//!
//! [`issue`] returns [`Refused`] rather than a certificate when the source
//! container does not verify, when a required particular is blank, or when both
//! signer records describe the same person. The last of these cannot establish
//! that the second signer is genuinely independent — no software can — but it
//! blocks the obvious failure, one person filling both roles.

mod pdf;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{now_utc, sha256, Manifest};

/// Bumped when the certificate layout changes incompatibly.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cited on every certificate, so one generated against an older reading of the
/// statute is identifiable as such later.
pub const STATUTE: &str = "Section 63, Bharatiya Sakshya Adhiniyam, 2023";

/// Reproduced verbatim and prominently on both outputs. Not fine print: it is
/// the sentence that stops the certificate being mistaken for a legal opinion.
pub const DISCLAIMER: &str = "This certificate is generated to align with the structure of \
Section 63, Bharatiya Sakshya Adhiniyam, 2023, based on records captured by Arachnid Forensic. \
It does not constitute legal advice, and does not itself guarantee admissibility. Consult \
qualified legal counsel before relying on this certificate in any proceeding.";

/// The four conditions of Section 63(2), as the certificate states them.
///
/// Each is an assertion by the people signing, not a measurement — the tool
/// cannot observe whether a computer was in regular use — so each is carried as
/// text and printed in full rather than as a checkbox a reader has to decode.
pub const CONDITIONS: [&str; 4] = [
    "The computer output containing the information was produced by a computer or communication \
     device that was in regular use over the period in question, by a person having lawful \
     control over its use.",
    "Information of the kind contained in the electronic record was regularly fed into the \
     computer or communication device in the ordinary course of those activities.",
    "The computer or communication device was operating properly throughout the material part of \
     that period; or, where it was not, any malfunction was not such as to affect the accuracy of \
     the electronic record.",
    "The information contained in the electronic record reproduces or is derived from information \
     fed into the computer or communication device in the ordinary course of those activities.",
];

// ---------------------------------------------------------------------------
// Facts pulled from the evidence container
// ---------------------------------------------------------------------------

/// One artifact as the custody log recorded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactFact {
    pub name: String,
    pub sha256: String,
    pub size: Option<u64>,
    pub logged_utc: Option<String>,
}

/// Everything on the certificate that came out of the evidence container.
///
/// Built only by [`SourceFacts::read`], which verifies before it reads, so no
/// field here can diverge from the signed log it was taken from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFacts {
    pub container_path: String,
    pub container_id: String,
    pub container_schema_version: String,
    pub tool: String,
    pub tool_version: String,
    pub collected_utc: String,
    pub collecting_operator: String,
    pub host: String,
    pub platform: String,
    /// Ed25519 key the custody log is signed under.
    pub custody_public_key: String,
    /// SHA-256 of that key: the value recorded out of band at collection.
    pub custody_key_fingerprint: String,
    pub custody_records: u64,
    pub artifacts_verified: u64,
    pub artifacts: Vec<ArtifactFact>,
    /// When the verification behind these facts was run.
    pub verified_utc: String,
}

impl SourceFacts {
    /// Verify a container and take the certificate's facts from it.
    ///
    /// Refuses on any verification problem. A certificate over evidence that
    /// does not check out is worse than no certificate: it lends the record an
    /// integrity claim the log itself will not support.
    pub fn read(root: &Path) -> Result<Self, Refused> {
        let report = crate::verify(root).map_err(|e| Refused::Unreadable(format!("{e:#}")))?;
        if !report.ok() {
            return Err(Refused::SourceDoesNotVerify(report.problems));
        }
        let raw = std::fs::read(root.join("manifest.json"))
            .map_err(|e| Refused::Unreadable(format!("read manifest.json: {e}")))?;
        let manifest: Manifest = serde_json::from_slice(&raw)
            .map_err(|e| Refused::Unreadable(format!("parse manifest.json: {e}")))?;

        Ok(SourceFacts {
            container_path: root.display().to_string(),
            container_id: manifest.container_id,
            container_schema_version: manifest.schema_version,
            tool: manifest.tool,
            tool_version: manifest.tool_version,
            collected_utc: manifest.created_utc,
            collecting_operator: manifest.operator,
            host: manifest.host,
            platform: manifest.platform,
            custody_public_key: report.public_key,
            custody_key_fingerprint: report.key_fingerprint,
            custody_records: report.records,
            artifacts_verified: report.artifacts_checked,
            artifacts: report
                .artifacts
                .into_iter()
                .filter_map(|a| {
                    Some(ArtifactFact {
                        name: a.name,
                        // A clean report has a digest for every artifact; a
                        // dry-run placeholder has none and is not evidence.
                        sha256: a.sha256?,
                        size: a.size,
                        logged_utc: a.logged_utc,
                    })
                })
                .collect(),
            verified_utc: now_utc(),
        })
    }
}

// ---------------------------------------------------------------------------
// What the signers supply
// ---------------------------------------------------------------------------

/// Which of the two Section 63(4) roles a signer is signing in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capacity {
    /// The person in charge of the computer or communication device.
    DeviceCustodian,
    /// The independent expert.
    IndependentExpert,
}

impl Capacity {
    pub fn label(self) -> &'static str {
        match self {
            Capacity::DeviceCustodian => "Person in charge of the computer or device",
            Capacity::IndependentExpert => "Independent expert",
        }
    }
}

/// One signer's identity, as that person gave it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub full_name: String,
    pub designation: String,
    pub organization: String,
    pub contact: String,
    pub capacity: Capacity,
    /// When this signer's details were recorded, RFC 3339 UTC.
    pub recorded_utc: String,
}

impl Signer {
    pub fn new(
        capacity: Capacity,
        full_name: impl Into<String>,
        designation: impl Into<String>,
        organization: impl Into<String>,
        contact: impl Into<String>,
    ) -> Self {
        Signer {
            full_name: full_name.into(),
            designation: designation.into(),
            organization: organization.into(),
            contact: contact.into(),
            capacity,
            recorded_utc: now_utc(),
        }
    }

    /// The identity tuple two signers must not share, normalized so that
    /// casing and spacing cannot be used to slip the same person through twice.
    fn identity(&self) -> (String, String, String) {
        let fold = |s: &str| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        };
        (
            fold(&self.full_name),
            fold(&self.organization),
            fold(&self.contact),
        )
    }

    fn missing_field(&self) -> Option<&'static str> {
        [
            ("full name", &self.full_name),
            ("designation", &self.designation),
            ("organization", &self.organization),
            ("contact", &self.contact),
        ]
        .into_iter()
        .find(|(_, v)| v.trim().is_empty())
        .map(|(label, _)| label)
    }
}

/// The Section 63(2) conditions as affirmed for this record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conditions {
    /// True when the device was operating properly throughout the material
    /// part of the period.
    pub operating_properly: bool,
    /// Required when it was not: what went wrong, and why the accuracy of the
    /// record was unaffected. Section 63(2) allows a malfunction; it does not
    /// allow one to go unstated.
    pub malfunction_note: Option<String>,
}

impl Conditions {
    /// The ordinary case: nothing malfunctioned.
    pub fn operating_properly() -> Self {
        Conditions {
            operating_properly: true,
            malfunction_note: None,
        }
    }

    /// A malfunction occurred, and this is the statement about it.
    pub fn with_malfunction(note: impl Into<String>) -> Self {
        Conditions {
            operating_properly: false,
            malfunction_note: Some(note.into()),
        }
    }
}

/// The particulars a person supplies for one certificate.
#[derive(Debug, Clone)]
pub struct Request {
    /// The case or reference number this record belongs to.
    pub case_reference: String,
    /// What the electronic record is, in the words a court will read.
    pub record_description: String,
    pub conditions: Conditions,
    pub custodian: Signer,
    pub expert: Signer,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a certificate was not issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The container could not be read at all.
    Unreadable(String),
    /// It was read, and it does not verify.
    SourceDoesNotVerify(Vec<String>),
    /// A statutory particular was left blank.
    MissingField(String),
    /// Both signer records describe the same person.
    SignersNotDistinct,
    /// A signer was recorded in the wrong Section 63(4) role.
    WrongCapacity,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Unreadable(why) => {
                write!(
                    f,
                    "no certificate: the evidence container could not be read ({why})"
                )
            }
            Refused::SourceDoesNotVerify(problems) => write!(
                f,
                "no certificate: the evidence container does not verify ({}). \
                 A certificate must not vouch for a record whose own custody log does not: {}",
                problems.len(),
                problems.join("; ")
            ),
            Refused::MissingField(what) => {
                write!(f, "no certificate: {what} is required and was left blank")
            }
            Refused::SignersNotDistinct => write!(
                f,
                "no certificate: both signers give the same name, organization and contact. \
                 Section 63(4) requires two different people — the person in charge of the \
                 device, and an independent expert"
            ),
            Refused::WrongCapacity => write!(
                f,
                "no certificate: one signer must sign as the device custodian and the other as \
                 the independent expert"
            ),
        }
    }
}

impl std::error::Error for Refused {}

// ---------------------------------------------------------------------------
// The certificate
// ---------------------------------------------------------------------------

/// The certificate body. Never carries a signature: see [`SignedCertificate`].
///
/// Field order is the serialization order and is part of the bytes an
/// attestation covers; do not reorder without bumping [`SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub statute: String,
    pub case_reference: String,
    pub record_description: String,
    pub source: SourceFacts,
    pub conditions: Conditions,
    /// The Section 63(2) conditions as printed on this certificate, carried in
    /// the JSON so a reader of the machine-readable form sees the same wording
    /// the signed paper does.
    pub condition_statements: Vec<String>,
    pub custodian: Signer,
    pub expert: Signer,
    pub disclaimer: String,
    pub generated_utc: String,
    pub generator: String,
    pub generator_version: String,
}

/// One signer's in-software attestation over the certificate body.
///
/// Deliberately not called a signature in the wet-ink sense. It proves that a
/// holder of this key approved these exact bytes; whether a court treats that
/// as execution of the certificate is a question for counsel, and the label
/// says so rather than assuming the answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub capacity: Capacity,
    pub signer_name: String,
    /// Ed25519 verifying key, hex.
    pub public_key: String,
    /// Ed25519 signature over the certificate body bytes, hex.
    pub signature: String,
    pub attested_utc: String,
    pub kind: String,
}

/// What lands on disk: the body, its digest, and any attestations over it.
///
/// The body is stored as its own object so an attestation covers exactly the
/// bytes `serde_json::to_vec(&certificate)` produces — nothing else in this
/// file is inside the signature, and `body_sha256` is what a verifier
/// recomputes to prove it re-serialized the same thing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificate {
    pub certificate: Certificate,
    pub body_sha256: String,
    /// Empty for the physical-signature path; one per signer for the
    /// in-software path.
    #[serde(default)]
    pub attestations: Vec<Attestation>,
}

/// Build a certificate, or refuse.
///
/// Verifies the container first and takes every machine-knowable fact from it,
/// so nothing auto-populated here can drift from the signed custody log.
pub fn issue(container: &Path, request: &Request) -> Result<SignedCertificate, Refused> {
    let source = SourceFacts::read(container)?;
    build(source, request)
}

/// The half of [`issue`] that does not touch the disk. Split out so a front end
/// that has already verified a container does not verify it a second time.
pub fn build(source: SourceFacts, request: &Request) -> Result<SignedCertificate, Refused> {
    if request.case_reference.trim().is_empty() {
        return Err(Refused::MissingField("the case or reference number".into()));
    }
    if request.record_description.trim().is_empty() {
        return Err(Refused::MissingField(
            "a description of the electronic record".into(),
        ));
    }
    if !request.conditions.operating_properly
        && request
            .conditions
            .malfunction_note
            .as_deref()
            .is_none_or(|n| n.trim().is_empty())
    {
        return Err(Refused::MissingField(
            "a statement of the malfunction and why it did not affect the accuracy of the record"
                .into(),
        ));
    }
    if request.custodian.capacity != Capacity::DeviceCustodian
        || request.expert.capacity != Capacity::IndependentExpert
    {
        return Err(Refused::WrongCapacity);
    }
    for (who, signer) in [
        ("the device custodian", &request.custodian),
        ("the independent expert", &request.expert),
    ] {
        if let Some(field) = signer.missing_field() {
            return Err(Refused::MissingField(format!("{who}'s {field}")));
        }
    }
    // Cannot prove independence — that is a human judgement, and this module
    // says so in its own documentation. It can refuse the obvious case.
    if request.custodian.identity() == request.expert.identity() {
        return Err(Refused::SignersNotDistinct);
    }

    let certificate = Certificate {
        schema_version: SCHEMA_VERSION.into(),
        // Derived from the container and the moment of generation rather than
        // from entropy, so two runs over the same container at the same instant
        // collide and everything else does not — and so the id is reproducible
        // from the certificate itself.
        certificate_id: sha256(
            format!(
                "{}|{}|{}",
                source.container_id,
                source.custody_key_fingerprint,
                now_utc()
            )
            .as_bytes(),
        )[..32]
            .to_string(),
        statute: STATUTE.into(),
        case_reference: request.case_reference.trim().into(),
        record_description: request.record_description.trim().into(),
        source,
        conditions: request.conditions.clone(),
        condition_statements: condition_statements(&request.conditions),
        custodian: request.custodian.clone(),
        expert: request.expert.clone(),
        disclaimer: DISCLAIMER.into(),
        generated_utc: now_utc(),
        generator: "arachnid-evidence".into(),
        generator_version: env!("CARGO_PKG_VERSION").into(),
    };

    let body = body_bytes(&certificate);
    Ok(SignedCertificate {
        body_sha256: sha256(&body),
        certificate,
        attestations: Vec::new(),
    })
}

/// Section 63(2) as it will be printed, with the malfunction statement folded
/// into condition (c) when there was one.
fn condition_statements(c: &Conditions) -> Vec<String> {
    let mut out: Vec<String> = CONDITIONS.iter().map(|s| (*s).to_string()).collect();
    if let Some(note) = c
        .malfunction_note
        .as_deref()
        .filter(|n| !n.trim().is_empty())
    {
        out[2].push_str(&format!(" Malfunction stated: {}", note.trim()));
    }
    out
}

/// The exact bytes an attestation covers.
///
/// `serde_json::to_vec` on a struct of owned fields cannot fail, so this does
/// not return a `Result` that every caller would have to thread through.
fn body_bytes(c: &Certificate) -> Vec<u8> {
    serde_json::to_vec(c).expect("a Certificate is plain owned data and always serializes")
}

impl SignedCertificate {
    /// Add one signer's in-software attestation over the body.
    ///
    /// The key belongs to the signer, not to the tool: the point of this path
    /// is that two people each approved these bytes with something only they
    /// hold.
    pub fn attest(&mut self, capacity: Capacity, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer as _;
        let signer = match capacity {
            Capacity::DeviceCustodian => &self.certificate.custodian,
            Capacity::IndependentExpert => &self.certificate.expert,
        };
        let sig = key.sign(&body_bytes(&self.certificate));
        self.attestations.push(Attestation {
            capacity,
            signer_name: signer.full_name.clone(),
            public_key: crate::hex(key.verifying_key().as_bytes()),
            signature: crate::hex(&sig.to_bytes()),
            attested_utc: now_utc(),
            kind: "in-software Ed25519 attestation; not a wet-ink or statutory e-signature".into(),
        });
    }

    /// Re-check the digest, every attestation, and the Section 63(4) shape of
    /// the attestation set. Returns the problems found, empty when the
    /// certificate is internally consistent.
    ///
    /// Independent of the writing path: it re-serializes the body and re-hashes
    /// it rather than trusting `body_sha256`, so a mismatch between the two is
    /// itself a finding.
    ///
    /// What an empty result does **not** mean: that these are the right people.
    /// A certificate is a self-contained document, so anyone able to rewrite it
    /// can rewrite the body, the digest and the attestations together with keys
    /// of their own making, and that forgery is internally consistent by
    /// construction. Authenticity rests on the keys, and this file is not a
    /// trustworthy source of them. To establish it, compare each attestation's
    /// `public_key` against the key that signer is independently known to hold
    /// — the same hex string is printed on the certificate itself, so paper and
    /// file can be checked against each other and against a key on record.
    pub fn check(&self) -> Vec<String> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let body = body_bytes(&self.certificate);
        let mut problems = Vec::new();
        if sha256(&body) != self.body_sha256 {
            problems.push("certificate body does not match its recorded digest".into());
        }
        for a in &self.attestations {
            let ok = crate::unhex(&a.public_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
                .zip(
                    crate::unhex(&a.signature)
                        .ok()
                        .and_then(|b| <[u8; 64]>::try_from(b).ok()),
                )
                .is_some_and(|(vk, sb)| vk.verify(&body, &Signature::from_bytes(&sb)).is_ok());
            if !ok {
                problems.push(format!(
                    "attestation by {} ({}) does not verify",
                    a.signer_name,
                    a.capacity.label()
                ));
            }
            // An attestation carries the name it was made under. If the body
            // now names someone else in that role, one of the two was edited.
            let named = match a.capacity {
                Capacity::DeviceCustodian => &self.certificate.custodian,
                Capacity::IndependentExpert => &self.certificate.expert,
            };
            if a.signer_name != named.full_name {
                problems.push(format!(
                    "the attestation made as {} was made by {}, but the certificate names {} in that role",
                    a.capacity.label(),
                    a.signer_name,
                    named.full_name
                ));
            }
        }
        // Section 63(4) is a rule about who signed, not only about whether each
        // signature verifies on its own. It is enforced at issue time, and it
        // is enforced again here: without this, a certificate stripped down to
        // one attestation — or attested twice by one person — reads as intact,
        // and the checker would accept what the issuer would have refused.
        if !self.attestations.is_empty() {
            for capacity in [Capacity::DeviceCustodian, Capacity::IndependentExpert] {
                let n = self
                    .attestations
                    .iter()
                    .filter(|a| a.capacity == capacity)
                    .count();
                if n != 1 {
                    problems.push(format!(
                        "Section 63(4) requires exactly one attestation as {}; this certificate carries {n}",
                        capacity.label()
                    ));
                }
            }
            let keys: std::collections::BTreeSet<&str> = self
                .attestations
                .iter()
                .map(|a| a.public_key.as_str())
                .collect();
            if keys.len() != self.attestations.len() {
                problems.push(
                    "one key made more than one attestation; that is one person attesting twice, not the two people Section 63(4) requires"
                        .into(),
                );
            }
        }
        problems
    }

    /// Fields whose text the PDF cannot render, one message each.
    ///
    /// The PDF uses the base-14 fonts, which carry a single byte-wide
    /// encoding; a name in Devanagari, Tamil or any other non-Latin script has
    /// no code point there and reaches the page as question marks. That is a
    /// real limit of this renderer and a serious one for an Indian court
    /// document, so it is reported to whoever is generating the certificate
    /// rather than discovered by a judge. The JSON output is UTF-8 and carries
    /// the text intact either way.
    ///
    /// Empty means every field renders exactly as entered.
    pub fn pdf_limitations(&self) -> Vec<String> {
        let c = &self.certificate;
        [
            ("case reference", &c.case_reference),
            ("record description", &c.record_description),
            ("device custodian's name", &c.custodian.full_name),
            ("device custodian's designation", &c.custodian.designation),
            ("device custodian's organization", &c.custodian.organization),
            ("device custodian's contact", &c.custodian.contact),
            ("independent expert's name", &c.expert.full_name),
            ("independent expert's designation", &c.expert.designation),
            ("independent expert's organization", &c.expert.organization),
            ("independent expert's contact", &c.expert.contact),
        ]
        .into_iter()
        .filter_map(|(field, value)| {
            let lost = pdf::unrepresentable(value);
            (!lost.is_empty()).then(|| {
                format!(
                    "the {field} contains {} the PDF cannot render ({}); it appears there as \
                     question marks. The JSON output carries it intact.",
                    if lost.len() == 1 {
                        "a character"
                    } else {
                        "characters"
                    },
                    lost.iter().collect::<String>()
                )
            })
        })
        .collect()
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self)
            .expect("a SignedCertificate is plain owned data and always serializes")
    }

    /// The certificate as a filing-ready PDF.
    ///
    /// Plain and formal on purpose: black on white, one typeface, no brand
    /// colour. This is a document for a court file, not a marketing asset.
    pub fn to_pdf(&self) -> Vec<u8> {
        render_pdf(self)
    }
}

fn render_pdf(signed: &SignedCertificate) -> Vec<u8> {
    use pdf::{Font, Pdf};

    let c = &signed.certificate;
    let s = &c.source;
    let mut d = Pdf::new();

    d.para("CERTIFICATE UNDER SECTION 63", Font::Bold, 15.0);
    d.para("BHARATIYA SAKSHYA ADHINIYAM, 2023", Font::Bold, 12.0);
    d.para(
        "In respect of an electronic record produced by a computer or communication device",
        Font::Regular,
        10.0,
    );
    d.gap(6.0);
    d.rule(1.4);
    d.gap(14.0);
    d.callout(DISCLAIMER);

    d.heading("1.  IDENTIFICATION OF THE ELECTRONIC RECORD");
    d.kv("Case / reference", &c.case_reference);
    d.kv("Electronic record", &c.record_description);
    d.kv("Produced by", &format!("{} {}", s.tool, s.tool_version));
    d.kv("Device / system", &format!("{} ({})", s.host, s.platform));
    d.kv("Collected (UTC)", &s.collected_utc);
    d.kv("Collecting operator", &s.collecting_operator);
    d.kv("Evidence container", &s.container_id);
    d.kv("Container location", &s.container_path);
    d.kv("Certificate ID", &c.certificate_id);

    d.heading("2.  CONDITIONS UNDER SECTION 63(2)");
    for (i, statement) in c.condition_statements.iter().enumerate() {
        d.para(
            &format!("({})  {statement}", (b'a' + i as u8) as char),
            Font::Regular,
            10.0,
        );
        d.gap(4.0);
    }

    d.heading("3.  INTEGRITY OF THE RECORD");
    d.para(
        "The electronic fingerprint below was recorded when each item was collected and was \
         re-computed from the stored data when this certificate was generated. The two match, so \
         the record has not been altered since capture.",
        Font::Regular,
        10.0,
    );
    d.gap(6.0);
    d.kv("Custody records", &s.custody_records.to_string());
    d.kv("Items re-verified", &s.artifacts_verified.to_string());
    d.kv("Custody signing key", &s.custody_public_key);
    d.kv("Key fingerprint", &s.custody_key_fingerprint);
    d.kv("Re-verified (UTC)", &s.verified_utc);
    d.gap(8.0);
    for a in &s.artifacts {
        d.kv(
            &a.name,
            &format!(
                "SHA-256 {}\n{} bytes, logged {}",
                a.sha256,
                a.size.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
                a.logged_utc.as_deref().unwrap_or("-")
            ),
        );
        d.gap(3.0);
    }

    d.heading("4.  SIGNATURES UNDER SECTION 63(4)");
    d.para(
        "This certificate is required to be signed by two different people: the person in charge \
         of the computer or communication device, and an independent expert. Neither signature \
         below may be given by the other's signatory.",
        Font::Regular,
        10.0,
    );
    for signer in [&c.custodian, &c.expert] {
        d.gap(10.0);
        d.para(signer.capacity.label(), Font::Bold, 10.5);
        d.gap(4.0);
        d.kv("Name", &signer.full_name);
        d.kv("Designation", &signer.designation);
        d.kv("Organisation", &signer.organization);
        d.kv("Contact", &signer.contact);
        d.kv("Details recorded", &signer.recorded_utc);
        d.kv("Date", "");
        d.signature_line(&format!("Signature — {}", signer.full_name));
    }

    if signed.attestations.is_empty() {
        d.gap(4.0);
        d.para(
            "No in-software attestation was recorded for this certificate. It is to be executed \
             by signature on this page.",
            Font::Regular,
            9.5,
        );
    } else {
        d.gap(10.0);
        d.para("In-software attestations", Font::Bold, 10.5);
        d.gap(4.0);
        d.para(
            "Each attestation below records that the holder of the stated key approved the exact \
             certificate body identified by the digest in section 5. An in-software attestation \
             is not represented as equivalent to a wet-ink signature.",
            Font::Regular,
            9.5,
        );
        d.gap(4.0);
        for a in &signed.attestations {
            d.kv(
                &a.signer_name,
                &format!(
                    "{}\nkey {}\nattested {}",
                    a.capacity.label(),
                    a.public_key,
                    a.attested_utc
                ),
            );
            d.gap(3.0);
        }
    }

    d.heading("5.  STATUTE, GENERATION AND LIMITS");
    d.kv("Statute", &c.statute);
    d.kv("Template version", &c.schema_version);
    d.kv("Generated (UTC)", &c.generated_utc);
    d.kv(
        "Generated by",
        &format!("{} {}", c.generator, c.generator_version),
    );
    d.kv("Body digest (SHA-256)", &signed.body_sha256);
    d.gap(8.0);
    d.para(
        "The independence of the second signer is a matter of human and procedural judgement. \
         Arachnid Forensic does not and cannot verify it; it only refuses a certificate where \
         both signers give the same name, organisation and contact details.",
        Font::Regular,
        9.5,
    );
    d.gap(6.0);
    d.para(DISCLAIMER, Font::Bold, 9.5);

    d.finish(&format!(
        "{} · certificate {} · {}",
        STATUTE, c.certificate_id, c.case_reference
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Container;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("arachnid-bsa63-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn container(tag: &str) -> PathBuf {
        let root = tmpdir(tag);
        let mut c = Container::create(&root, "analyst@lab", None, false).unwrap();
        c.add_bytes("processes.json", b"[]").unwrap();
        c.add_bytes("connections.json", b"[]").unwrap();
        c.finish().unwrap();
        root
    }

    fn request() -> Request {
        Request {
            case_reference: "FIR 118/2026, Cyber PS".into(),
            record_description: "Volatile system state collected from workstation FIN-04".into(),
            conditions: Conditions::operating_properly(),
            custodian: Signer::new(
                Capacity::DeviceCustodian,
                "A. Kulkarni",
                "IT Manager",
                "Northwind Ltd",
                "a.kulkarni@northwind.example",
            ),
            expert: Signer::new(
                Capacity::IndependentExpert,
                "R. Mehta",
                "Digital Forensic Examiner",
                "State Forensic Science Laboratory",
                "r.mehta@sfsl.example",
            ),
        }
    }

    /// The point of the feature: every auto-populated field is the one in the
    /// container's own signed log, not a re-derivation of it.
    #[test]
    fn auto_populated_fields_match_the_source_evidence_log() {
        let root = container("populate");
        let signed = issue(&root, &request()).expect("should issue");
        let s = &signed.certificate.source;

        let report = crate::verify(&root).unwrap();
        let manifest: Manifest =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();

        assert_eq!(s.container_id, manifest.container_id);
        assert_eq!(s.collected_utc, manifest.created_utc);
        assert_eq!(s.collecting_operator, manifest.operator);
        assert_eq!(s.host, manifest.host);
        assert_eq!(s.custody_public_key, manifest.public_key);
        assert_eq!(s.custody_key_fingerprint, report.key_fingerprint);
        assert_eq!(s.custody_records, report.records);
        assert_eq!(s.artifacts.len(), 2);
        for a in &s.artifacts {
            let logged = report
                .artifacts
                .iter()
                .find(|r| r.name == a.name)
                .expect("every certificate artifact comes from the log");
            assert_eq!(Some(a.sha256.clone()), logged.sha256);
            assert_eq!(a.size, logged.size);
            assert_eq!(a.logged_utc, logged.logged_utc);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_tampered_container_is_refused() {
        let root = container("tamper");
        std::fs::write(root.join("artifacts/processes.json"), b"[1]").unwrap();
        match issue(&root, &request()) {
            Err(Refused::SourceDoesNotVerify(problems)) => {
                assert!(problems.iter().any(|p| p.contains("content modified")));
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_container_is_refused_rather_than_panicking() {
        let root = tmpdir("absent");
        assert!(matches!(
            issue(&root, &request()),
            Err(Refused::Unreadable(_))
        ));
    }

    /// Section 63(4) wants two people. Casing and spacing must not get one
    /// person past that.
    #[test]
    fn identical_signers_are_rejected() {
        let root = container("same");
        let mut r = request();
        r.expert = Signer::new(
            Capacity::IndependentExpert,
            "  a.   KULKARNI ",
            "Independent Expert",
            "NORTHWIND ltd",
            "A.Kulkarni@Northwind.Example",
        );
        assert_eq!(issue(&root, &r).unwrap_err(), Refused::SignersNotDistinct);

        // Designation alone differing is not enough; a different person is.
        let mut ok = request();
        ok.expert.full_name = "R. Mehta".into();
        assert!(issue(&root, &ok).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn blank_particulars_are_refused() {
        let root = container("blank");
        for mutate in [
            (|r: &mut Request| r.case_reference = "  ".into()) as fn(&mut Request),
            |r: &mut Request| r.record_description = String::new(),
            |r: &mut Request| r.custodian.contact = String::new(),
            |r: &mut Request| r.expert.designation = " ".into(),
        ] {
            let mut r = request();
            mutate(&mut r);
            assert!(
                matches!(issue(&root, &r), Err(Refused::MissingField(_))),
                "a blank statutory particular must be refused"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A malfunction is allowed by the statute; leaving it unexplained is not.
    #[test]
    fn an_unexplained_malfunction_is_refused_and_an_explained_one_is_printed() {
        let root = container("malfunction");
        let mut r = request();
        r.conditions = Conditions {
            operating_properly: false,
            malfunction_note: None,
        };
        assert!(matches!(issue(&root, &r), Err(Refused::MissingField(_))));

        r.conditions = Conditions::with_malfunction(
            "A disk in the RAID set failed and was rebuilt; the collected volume was not affected.",
        );
        let signed = issue(&root, &r).unwrap();
        assert!(signed.certificate.condition_statements[2].contains("Malfunction stated:"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_capacities_have_to_be_the_two_statutory_roles() {
        let root = container("capacity");
        let mut r = request();
        r.expert.capacity = Capacity::DeviceCustodian;
        assert_eq!(issue(&root, &r).unwrap_err(), Refused::WrongCapacity);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_disclaimer_is_embedded_verbatim_in_both_outputs() {
        let root = container("disclaimer");
        let signed = issue(&root, &request()).unwrap();

        let json = String::from_utf8(signed.to_json()).unwrap();
        let parsed: SignedCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.certificate.disclaimer, DISCLAIMER);

        let pdf = String::from_utf8(signed.to_pdf()).expect("the writer emits ASCII only");
        assert!(pdf.starts_with("%PDF-1.4"));
        // Wrapping puts each line in its own `Tj`, so compare the page text
        // with whitespace removed: that is the disclaimer verbatim, laid out.
        let squash = |s: &str| s.split_whitespace().collect::<String>();
        assert!(
            squash(&shown_text(&pdf)).contains(&squash(DISCLAIMER)),
            "the PDF must carry the disclaimer verbatim"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Every string the PDF actually draws, in order — the page as a reader
    /// sees it, recovered from the content streams.
    fn shown_text(pdf: &str) -> String {
        pdf.split(") Tj")
            .filter_map(|chunk| chunk.rsplit_once('(').map(|(_, text)| text))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The PDF's base-14 fonts cannot encode Devanagari. That is reported, per
    /// field, rather than left to be discovered on the printed page.
    #[test]
    fn a_name_the_pdf_cannot_render_is_reported() {
        let root = container("script");
        let mut r = request();
        r.expert.full_name = "आर. मेहता".into();

        let signed = issue(&root, &r).unwrap();
        let limits = signed.pdf_limitations();
        assert_eq!(limits.len(), 1, "{limits:?}");
        assert!(
            limits[0].contains("independent expert's name"),
            "{limits:?}"
        );

        // The JSON keeps the name; only the PDF loses it.
        let parsed: SignedCertificate = serde_json::from_slice(&signed.to_json()).unwrap();
        assert_eq!(parsed.certificate.expert.full_name, "आर. मेहता");

        assert!(issue(&root, &request())
            .unwrap()
            .pdf_limitations()
            .is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn in_software_attestations_sign_the_body_and_verify() {
        use ed25519_dalek::SigningKey;
        let root = container("attest");
        let mut signed = issue(&root, &request()).unwrap();
        assert!(signed.check().is_empty());

        signed.attest(
            Capacity::DeviceCustodian,
            &SigningKey::from_bytes(&[7u8; 32]),
        );
        signed.attest(
            Capacity::IndependentExpert,
            &SigningKey::from_bytes(&[9u8; 32]),
        );
        assert_eq!(signed.attestations.len(), 2);
        assert!(signed.check().is_empty(), "{:?}", signed.check());

        // Round-tripping through JSON must not disturb the signed bytes.
        let reparsed: SignedCertificate = serde_json::from_slice(&signed.to_json()).unwrap();
        assert!(reparsed.check().is_empty(), "{:?}", reparsed.check());

        // Editing the body after attestation breaks both the digest and the
        // signatures over it.
        let mut edited = signed.clone();
        edited.certificate.case_reference = "FIR 999/2026".into();
        let problems = edited.check();
        assert!(problems.iter().any(|p| p.contains("recorded digest")));
        assert_eq!(problems.len(), 3);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_checker_holds_attestations_to_the_rule_the_issuer_applied() {
        use ed25519_dalek::SigningKey;
        let root = container("attest-shape");
        let custodian = SigningKey::from_bytes(&[7u8; 32]);
        let expert = SigningKey::from_bytes(&[9u8; 32]);

        // Dropping one signer leaves a certificate whose remaining signature is
        // perfectly good and which Section 63(4) still does not satisfy.
        let mut alone = issue(&root, &request()).unwrap();
        alone.attest(Capacity::DeviceCustodian, &custodian);
        let problems = alone.check();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("Independent expert"));

        // One person holding one key cannot be both signers.
        let mut twice = issue(&root, &request()).unwrap();
        twice.attest(Capacity::DeviceCustodian, &custodian);
        twice.attest(Capacity::IndependentExpert, &custodian);
        assert!(twice
            .check()
            .iter()
            .any(|p| p.contains("one person attesting twice")));

        // Renaming a signer after they attested is an edit the digest catches,
        // and the name on the attestation catches it a second time.
        let mut renamed = issue(&root, &request()).unwrap();
        renamed.attest(Capacity::DeviceCustodian, &custodian);
        renamed.attest(Capacity::IndependentExpert, &expert);
        renamed.certificate.expert.full_name = "Someone Else".into();
        assert!(renamed
            .check()
            .iter()
            .any(|p| p.contains("the certificate names Someone Else in that role")));

        std::fs::remove_dir_all(&root).unwrap();
    }
}
