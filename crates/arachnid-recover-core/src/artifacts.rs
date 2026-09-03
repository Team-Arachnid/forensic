//! Identifying the three artifacts an investigation asks for by name: call
//! logs, browser history and system logs.
//!
//! Recovery gets a file back. It does not, on its own, tell an analyst which of
//! ten thousand recovered files is the call log — and on a phone or a laptop
//! image those three classes are usually the first thing anyone wants. So every
//! result is checked against what is known about where these artifacts live and
//! what they contain, and the ones that match carry a class a `--type` filter
//! can select on.
//!
//! Two routes in, matching the two kinds of claim this crate already makes.
//!
//! **By path.** A filesystem-recovered file still has its name, and the name is
//! evidence: `places.sqlite` is Firefox's history store wherever it was found,
//! and anything under `/var/log/` is a system log.
//!
//! **By content.** A carved file has no name, so the only thing left to read is
//! the file itself. A SQLite database carries its schema as text on page one, so
//! the table names say what the database is — `moz_places` is Firefox,
//! `ZCALLRECORD` is the iOS call history. The two binary log formats, Windows
//! EVTX and the systemd journal, are identified by the signature the carver
//! matched them on to begin with.
//!
//! The label is a claim like every other claim here, so it is never silent: an
//! identified file carries an `artifact_identified` check naming the route and
//! the evidence. And a generic name is deliberately not enough — a bare
//! `History` with no browser directory above it is left unlabelled, because the
//! cost of a wrong label is an analyst reading an unrelated file as a suspect's
//! browsing.

use crate::results::{Check, RecoveredFile};

/// Android's `calllog.db` and `contacts2.db`, iOS's `CallHistory.storedata`.
pub const CALL_LOG: &str = "call-log";
/// Chromium's `History`, Firefox's `places.sqlite`, Safari's `History.db`.
pub const BROWSER_HISTORY: &str = "browser-history";
/// `/var/log`, the Windows event logs, the systemd journal.
pub const SYSTEM_LOG: &str = "system-log";

/// Every class, for the summary block and for `--type`.
pub const CLASSES: [&str; 3] = [CALL_LOG, BROWSER_HISTORY, SYSTEM_LOG];

/// One identification, and the evidence for it.
pub struct Match {
    pub class: &'static str,
    /// What was actually matched. Goes onto the result's checks verbatim.
    pub why: String,
}

impl Match {
    fn new(class: &'static str, why: impl Into<String>) -> Self {
        Match {
            class,
            why: why.into(),
        }
    }

    /// Record the identification on `file`: the field a filter reads, and the
    /// check an analyst reads.
    pub fn apply(self, file: &mut RecoveredFile) {
        file.rationale.checks.push(Check::pass(
            "artifact_identified",
            format!("{}: {}", self.class, self.why),
        ));
        file.artifact = Some(self.class.to_string());
    }
}

/// Filenames that identify an artifact wherever they were found. Every one
/// belongs to a single application's store; nothing generic is listed here.
const NAMES: &[(&str, &str)] = &[
    ("calllog.db", CALL_LOG),
    ("call_log.db", CALL_LOG),
    // Android keeps the call log in the contacts provider's database.
    ("contacts2.db", CALL_LOG),
    ("callhistory.storedata", CALL_LOG),
    ("call_history.db", CALL_LOG),
    ("places.sqlite", BROWSER_HISTORY),
    ("webcachev01.dat", BROWSER_HISTORY),
    ("syslog", SYSTEM_LOG),
    ("auth.log", SYSTEM_LOG),
    ("kern.log", SYSTEM_LOG),
    ("system.log", SYSTEM_LOG),
];

/// Directories whose contents are the artifact, whatever the file is called.
const DIRECTORIES: &[(&str, &str)] = &[
    ("/var/log/", SYSTEM_LOG),
    ("winevt/logs/", SYSTEM_LOG),
    ("/log/journal/", SYSTEM_LOG),
];

/// File types that are an artifact by definition — an extension on a recovered
/// path, or the carver's own name for the signature it matched.
const TYPES: &[(&str, &str)] = &[
    ("evtx", SYSTEM_LOG),
    ("evt", SYSTEM_LOG),
    ("journal", SYSTEM_LOG),
];

/// Names a browser uses that are too generic to act on alone. `History` is a
/// Chromium history database inside a browser profile and an ordinary file
/// anywhere else, so one of [`BROWSER_DIRS`] has to appear above it.
const BROWSER_NAMES: &[&str] = &["history", "history.db", "archivedhistory"];

const BROWSER_DIRS: &[&str] = &[
    "chrome",
    "chromium",
    "edge",
    "brave",
    "opera",
    "vivaldi",
    "safari",
    "firefox",
    "mozilla",
    "user data",
];

/// Table and column names that appear verbatim in a SQLite schema page, each
/// unique to one application's store.
const SCHEMA: &[(&str, &str, &str)] = &[
    (
        "moz_places",
        BROWSER_HISTORY,
        "the Firefox places.sqlite schema",
    ),
    (
        "visit_duration",
        BROWSER_HISTORY,
        "the Chromium history schema",
    ),
    (
        "history_visits",
        BROWSER_HISTORY,
        "the Safari History.db schema",
    ),
    (
        "ZCALLRECORD",
        CALL_LOG,
        "the iOS CallHistory Core Data schema",
    ),
    (
        "CREATE TABLE calls",
        CALL_LOG,
        "the Android call log schema",
    ),
    ("voicemail_uri", CALL_LOG, "the Android call log schema"),
];

/// Identify an artifact from a recovered file's original path.
pub fn from_path(path: &str) -> Option<Match> {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    if let Some(&(n, class)) = NAMES.iter().find(|(n, _)| *n == name) {
        return Some(Match::new(class, format!("{n} is that store's filename")));
    }
    if let Some(&(dir, class)) = DIRECTORIES.iter().find(|(d, _)| lower.contains(d)) {
        return Some(Match::new(
            class,
            format!("the file was stored under {dir}"),
        ));
    }
    if let Some(m) = from_type(&crate::ntfs::extension_of(name)) {
        return Some(m);
    }
    if BROWSER_NAMES.contains(&name) {
        if let Some(dir) = BROWSER_DIRS.iter().find(|d| lower.contains(**d)) {
            return Some(Match::new(
                BROWSER_HISTORY,
                format!("{name} inside a {dir} profile directory"),
            ));
        }
    }
    None
}

/// Identify an artifact from a file type: an extension on a recovered path, or
/// the name the carver knows a signature by.
pub fn from_type(file_type: &str) -> Option<Match> {
    TYPES
        .iter()
        .find(|(t, _)| t.eq_ignore_ascii_case(file_type))
        .map(|&(t, class)| Match::new(class, format!("the file is in the {t} log format")))
}

/// Identify a carved SQLite database from its schema page.
pub fn from_content(head: &[u8]) -> Option<Match> {
    SCHEMA
        .iter()
        .find(|(needle, _, _)| crate::carve::find(head, needle.as_bytes()).is_some())
        .map(|&(needle, class, what)| {
            Match::new(
                class,
                format!("the schema names {needle:?}, which is {what}"),
            )
        })
}

/// Months as syslog writes them: the fixed English abbreviations, whatever the
/// host's locale.
const MONTHS: [&[u8]; 12] = [
    b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec",
];

/// Identify a carved run of text that opens with a syslog line.
///
/// RFC 3164's `Mmm dd hh:mm:ss` is fifteen characters with every one of them
/// pinned, which is what makes it safe to act on: ordinary prose does not start
/// that way by accident. It is still only the opening line, so the check
/// recorded on the result says exactly that and nothing more.
pub fn from_text(head: &[u8]) -> Option<Match> {
    let b = head.get(..15)?;
    let month = b[0..3].to_ascii_lowercase();
    let shaped = MONTHS.contains(&month.as_slice())
        && b[3] == b' '
        && (b[4].is_ascii_digit() || b[4] == b' ')
        && b[5].is_ascii_digit()
        && b[6] == b' '
        && b[7].is_ascii_digit()
        && b[8].is_ascii_digit()
        && b[9] == b':'
        && b[10].is_ascii_digit()
        && b[11].is_ascii_digit()
        && b[12] == b':'
        && b[13].is_ascii_digit()
        && b[14].is_ascii_digit();
    shaped.then(|| {
        Match::new(
            SYSTEM_LOG,
            "the block opens with an RFC 3164 syslog timestamp",
        )
    })
}

/// Label a filesystem-recovered file from its path.
///
/// Carved results are labelled by the carver instead, which has their content
/// and no path to go on, so anything already identified is left alone.
pub fn classify(file: &mut RecoveredFile) {
    if file.artifact.is_some() {
        return;
    }
    if let Some(m) = file.original_path.as_deref().and_then(from_path) {
        m.apply(file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(path: &str) -> Option<&'static str> {
        from_path(path).map(|m| m.class)
    }

    #[test]
    fn the_three_classes_are_found_by_path() {
        assert_eq!(
            class_of("Users/j/AppData/Local/Google/Chrome/User Data/Default/History"),
            Some(BROWSER_HISTORY)
        );
        assert_eq!(
            class_of("home/j/.mozilla/firefox/ab12.default/places.sqlite"),
            Some(BROWSER_HISTORY)
        );
        assert_eq!(
            class_of("data/data/com.android.providers.contacts/databases/calllog.db"),
            Some(CALL_LOG)
        );
        assert_eq!(
            class_of("private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"),
            Some(CALL_LOG)
        );
        assert_eq!(class_of("var/log/auth.log"), Some(SYSTEM_LOG));
        assert_eq!(
            class_of("Windows\\System32\\winevt\\Logs\\Security.evtx"),
            Some(SYSTEM_LOG)
        );
    }

    /// The whole reason a browser profile directory is required. A bare
    /// `History` is a filename anyone can use, and mislabelling one as a
    /// suspect's browsing is worse than not labelling it at all.
    #[test]
    fn a_generic_name_alone_is_not_enough() {
        assert_eq!(class_of("Documents/History"), None);
        assert_eq!(class_of("Users/j/Desktop/notes.db"), None);
        assert_eq!(class_of("var/lib/app/data.sqlite"), None);
        // But the same name inside a browser profile is.
        assert_eq!(
            class_of("Users/j/Library/Safari/History.db"),
            Some(BROWSER_HISTORY)
        );
    }

    #[test]
    fn a_carved_database_is_identified_by_its_schema() {
        let firefox = b"CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR)";
        assert_eq!(
            from_content(firefox).map(|m| m.class),
            Some(BROWSER_HISTORY)
        );
        let android = b"CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT)";
        assert_eq!(from_content(android).map(|m| m.class), Some(CALL_LOG));
        assert!(from_content(b"CREATE TABLE notes (body TEXT)").is_none());
    }

    #[test]
    fn a_syslog_opening_line_is_recognised_and_prose_is_not() {
        assert_eq!(
            from_text(b"Aug 29 14:03:11 web01 sshd[1201]: Accepted publickey").map(|m| m.class),
            Some(SYSTEM_LOG)
        );
        // Single-digit day: syslog pads it with a space.
        assert!(from_text(b"Sep  3 00:00:01 host cron[9]: run").is_some());
        assert!(from_text(b"Dear Aug 29 14:03:11, this is a letter").is_none());
        assert!(from_text(b"Aug 29 1:3:11 malformed").is_none());
        assert!(from_text(b"short").is_none());
    }
}
