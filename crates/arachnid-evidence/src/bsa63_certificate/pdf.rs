//! Just enough of PDF 1.4 to lay out a plain, formal, text-only document.
//!
//! A court certificate is a page of headings, labelled values and ruled
//! signature lines. That is a few hundred lines of writer against the two
//! base-14 fonts every reader ships, or a PDF crate and the dependency tree
//! under it — in a workspace that hand-rolls its own markdown subset rather
//! than take one. So: written here, deliberately small, and deliberately
//! incapable of images, colour or embedded fonts.
//!
//! The output is A4, Helvetica and Helvetica-Bold, WinAnsi-encoded, with every
//! byte above 127 escaped in octal so the file itself stays pure ASCII.
//!
//! Column widths come from an average-advance estimate rather than the Helvetica
//! metrics table, so wrapping is conservative: lines break a little early rather
//! than a little late. For a document of headings and short values that is the
//! trade worth making.

/// A4 in points.
const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 56.0;
/// Reserved at the foot of every page for the running footer.
const FOOTER_Y: f32 = 40.0;
/// New page once the cursor drops below this.
const FLOOR: f32 = 72.0;
/// Width of the label column in a [`Pdf::kv`] row.
const LABEL_W: f32 = 150.0;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Font {
    Regular,
    Bold,
}

impl Font {
    fn resource(self) -> &'static str {
        match self {
            Font::Regular => "/F1",
            Font::Bold => "/F2",
        }
    }

    /// Average advance as a fraction of the font size. Helvetica's mixed-case
    /// average sits near 0.5; the margin above it is what keeps an unlucky line
    /// of capitals inside the page.
    fn advance(self) -> f32 {
        match self {
            Font::Regular => 0.55,
            Font::Bold => 0.58,
        }
    }
}

/// A document under construction. Content is emitted page by page as the cursor
/// walks down; nothing is buffered for a second pass, so there is no reflow.
pub struct Pdf {
    pages: Vec<String>,
    current: String,
    y: f32,
}

impl Default for Pdf {
    fn default() -> Self {
        Self::new()
    }
}

impl Pdf {
    pub fn new() -> Self {
        Pdf {
            pages: Vec::new(),
            current: String::new(),
            y: PAGE_H - MARGIN,
        }
    }

    fn text_width() -> f32 {
        PAGE_W - 2.0 * MARGIN
    }

    /// Characters that fit in `width` at this font and size. At least one, so a
    /// pathological width cannot loop forever.
    fn columns(width: f32, font: Font, size: f32) -> usize {
        ((width / (size * font.advance())) as usize).max(1)
    }

    fn break_page(&mut self) {
        self.pages.push(std::mem::take(&mut self.current));
        self.y = PAGE_H - MARGIN;
    }

    fn room_for(&mut self, height: f32) {
        if self.y - height < FLOOR {
            self.break_page();
        }
    }

    /// Draw one already-fitting line at an absolute x.
    fn show(&mut self, x: f32, s: &str, font: Font, size: f32) {
        self.current.push_str(&format!(
            "BT {} {size} Tf 1 0 0 1 {x:.1} {y:.1} Tm ({}) Tj ET\n",
            font.resource(),
            escape(s),
            y = self.y
        ));
    }

    /// Vertical space, in points.
    pub fn gap(&mut self, h: f32) {
        self.y -= h;
    }

    /// A wrapped paragraph at the left margin.
    pub fn para(&mut self, s: &str, font: Font, size: f32) {
        let cols = Self::columns(Self::text_width(), font, size);
        let leading = size * 1.35;
        for line in wrap(s, cols) {
            self.room_for(leading);
            self.show(MARGIN, &line, font, size);
            self.y -= leading;
        }
    }

    /// A numbered section heading, with the rule under it.
    pub fn heading(&mut self, s: &str) {
        self.gap(8.0);
        self.room_for(30.0);
        self.show(MARGIN, s, Font::Bold, 11.0);
        self.y -= 4.0;
        self.rule(1.0);
        self.y -= 10.0;
    }

    /// A label/value row. The value wraps into the remaining width with a
    /// hanging indent, so a 64-character digest does not push a page open.
    pub fn kv(&mut self, label: &str, value: &str) {
        let size = 10.0;
        let leading = size * 1.35;
        let cols = Self::columns(Self::text_width() - LABEL_W, Font::Regular, size);
        // `wrap` always yields at least one line, so a label whose value is
        // empty still appears: a statutory field must never silently vanish.
        let lines = wrap(value, cols);
        self.room_for(leading * lines.len() as f32);
        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                self.show(MARGIN, label, Font::Bold, size);
            }
            self.show(MARGIN + LABEL_W, line, Font::Regular, size);
            self.y -= leading;
        }
    }

    /// A full-width horizontal rule.
    pub fn rule(&mut self, weight: f32) {
        self.room_for(weight + 2.0);
        self.current.push_str(&format!(
            "{weight:.2} w {:.1} {y:.1} m {:.1} {y:.1} l S\n",
            MARGIN,
            PAGE_W - MARGIN,
            y = self.y
        ));
    }

    /// A ruled line to sign on, and its caption underneath.
    pub fn signature_line(&mut self, caption: &str) {
        self.gap(26.0);
        self.room_for(30.0);
        self.current.push_str(&format!(
            "0.8 w {:.1} {y:.1} m {:.1} {y:.1} l S\n",
            MARGIN,
            MARGIN + 260.0,
            y = self.y
        ));
        self.y -= 12.0;
        self.show(MARGIN, caption, Font::Regular, 9.0);
        self.y -= 12.0;
    }

    /// A boxed callout — used for the disclaimer, which must not read as fine
    /// print.
    pub fn callout(&mut self, s: &str) {
        let size = 9.5;
        let cols = Self::columns(Self::text_width() - 24.0, Font::Bold, size);
        let lines = wrap(s, cols);
        let leading = size * 1.35;
        let height = leading * lines.len() as f32 + 20.0;
        self.room_for(height);
        let top = self.y;
        self.y -= 14.0;
        for line in lines {
            self.show(MARGIN + 12.0, &line, Font::Bold, size);
            self.y -= leading;
        }
        let bottom = self.y - 6.0;
        self.current.push_str(&format!(
            "1 w {x0:.1} {top:.1} m {x1:.1} {top:.1} l {x1:.1} {bottom:.1} l \
             {x0:.1} {bottom:.1} l h S\n",
            x0 = MARGIN,
            x1 = PAGE_W - MARGIN,
        ));
        self.y = bottom - 12.0;
    }

    /// Close the document, stamping `footer` at the foot of every page.
    ///
    /// The page count is only known here, which is why the footer is applied at
    /// the end rather than as each page is opened.
    pub fn finish(mut self, footer: &str) -> Vec<u8> {
        self.break_page();
        let total = self.pages.len();
        let stamped: Vec<String> = self
            .pages
            .iter()
            .enumerate()
            .map(|(i, page)| {
                format!(
                    "{page}BT /F1 8 Tf 1 0 0 1 {MARGIN:.1} {FOOTER_Y:.1} Tm ({}) Tj ET\n",
                    escape(&format!("{footer}  ·  page {} of {total}", i + 1))
                )
            })
            .collect();
        assemble(&stamped)
    }
}

/// Greedy wrap at `cols` characters, honouring explicit newlines. A word longer
/// than the column count is broken rather than allowed to run off the page — a
/// SHA-256 digest is exactly that word.
fn wrap(s: &str, cols: usize) -> Vec<String> {
    let mut out = Vec::new();
    for paragraph in s.split('\n') {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            let mut word = word;
            while word.chars().count() > cols {
                if !line.is_empty() {
                    out.push(std::mem::take(&mut line));
                }
                let head: String = word.chars().take(cols).collect();
                let taken = head.len();
                out.push(head);
                word = &word[taken..];
            }
            if line.is_empty() {
                line.push_str(word);
            } else if line.chars().count() + 1 + word.chars().count() <= cols {
                line.push(' ');
                line.push_str(word);
            } else {
                out.push(std::mem::replace(&mut line, word.to_string()));
            }
        }
        out.push(line);
    }
    out
}

/// This character's WinAnsi code point, if it has one.
///
/// WinAnsi is Latin-1 with the C1 range replaced by typography — the curly
/// quotes and dashes that ordinary prose is full of. Mapping them matters:
/// without it an em dash pasted into a name would reach a court document as a
/// question mark, silently.
fn win_ansi(c: char) -> Option<u8> {
    Some(match c {
        '\u{20ac}' => 0x80,
        '\u{201a}' => 0x82,
        '\u{0192}' => 0x83,
        '\u{201e}' => 0x84,
        '\u{2026}' => 0x85,
        '\u{2020}' => 0x86,
        '\u{2021}' => 0x87,
        '\u{02c6}' => 0x88,
        '\u{2030}' => 0x89,
        '\u{0160}' => 0x8a,
        '\u{2039}' => 0x8b,
        '\u{0152}' => 0x8c,
        '\u{017d}' => 0x8e,
        '\u{2018}' => 0x91,
        '\u{2019}' => 0x92,
        '\u{201c}' => 0x93,
        '\u{201d}' => 0x94,
        '\u{2022}' => 0x95,
        '\u{2013}' => 0x96,
        '\u{2014}' => 0x97,
        '\u{02dc}' => 0x98,
        '\u{2122}' => 0x99,
        '\u{0161}' => 0x9a,
        '\u{203a}' => 0x9b,
        '\u{0153}' => 0x9c,
        '\u{017e}' => 0x9e,
        '\u{0178}' => 0x9f,
        c if ('\u{a0}'..='\u{ff}').contains(&c) => c as u8,
        _ => return None,
    })
}

/// Characters in `s` this writer cannot put on a page, deduplicated.
///
/// The base-14 fonts carry one byte-wide encoding and no more; a Devanagari or
/// Tamil name has no code point here and would be dropped. Callers surface this
/// rather than letting a certificate quietly lose a signer's name — see
/// [`super::SignedCertificate::pdf_limitations`].
pub fn unrepresentable(s: &str) -> Vec<char> {
    let mut out: Vec<char> = Vec::new();
    for c in s.chars() {
        if !matches!(c, ' '..='~') && win_ansi(c).is_none() && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// PDF literal string: parentheses and backslashes escaped, everything outside
/// printable ASCII written as an octal escape so the file stays ASCII-clean.
/// A character with no WinAnsi code point becomes `?`; [`unrepresentable`] is
/// how a caller finds out before that happens.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => match win_ansi(c) {
                Some(b) => out.push_str(&format!("\\{b:03o}")),
                None => out.push('?'),
            },
        }
    }
    out
}

/// Stitch the object graph together and write the cross-reference table.
fn assemble(pages: &[String]) -> Vec<u8> {
    // 1 catalog, 2 page tree, 3 and 4 the fonts, then a page and a content
    // stream object per page.
    let first_page_obj = 5;
    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", first_page_obj + 2 * i))
        .collect();

    let mut objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".into(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            pages.len()
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .into(),
    ];
    for (i, content) in pages.iter().enumerate() {
        let stream_obj = first_page_obj + 2 * i + 1;
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] \
             /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {stream_obj} 0 R >>"
        ));
        objects.push(format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ));
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_broken_rather_than_run_off_the_page() {
        let digest = "a".repeat(64);
        let lines = wrap(&digest, 20);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|l| l.chars().count() <= 20));
        assert_eq!(lines.concat(), digest);
    }

    #[test]
    fn wrapping_keeps_words_whole_and_honours_newlines() {
        assert_eq!(wrap("one two three", 8), ["one two", "three"]);
        assert_eq!(wrap("a\nb", 40), ["a", "b"]);
    }

    #[test]
    fn strings_are_escaped_into_pure_ascii() {
        assert_eq!(escape("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(escape("café"), "caf\\351");
        // The typography ordinary prose is full of has WinAnsi code points and
        // must not degrade into question marks on a court document.
        assert_eq!(escape("a—b"), "a\\227b");
        assert_eq!(escape("\u{2018}q\u{2019}"), "\\221q\\222");
        assert!(escape("ä€\u{2014}").is_ascii());
    }

    /// A script the base-14 fonts cannot encode has to be reported, not
    /// silently replaced — a signer's name is not a field to lose quietly.
    #[test]
    fn characters_with_no_encoding_are_reported_and_then_replaced() {
        assert!(unrepresentable("A. Kulkarni — IT Manager, café").is_empty());
        assert_eq!(unrepresentable("देव"), ['द', 'े', 'व']);
        assert_eq!(escape("देव"), "???");
    }

    /// The cross-reference offsets are what a reader seeks on; if they drift
    /// from the object positions the file opens as corrupt.
    #[test]
    fn the_xref_offsets_point_at_their_objects() {
        let mut pdf = Pdf::new();
        pdf.para("hello", Font::Regular, 11.0);
        let bytes = pdf.finish("test");
        let text = String::from_utf8_lossy(&bytes).into_owned();

        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.ends_with("%%EOF\n"));

        let xref_at: usize = text
            .rsplit("startxref\n")
            .next()
            .and_then(|t| t.split('\n').next())
            .unwrap()
            .parse()
            .unwrap();
        assert!(text[xref_at..].starts_with("xref\n"));

        for (i, entry) in text[xref_at..]
            .lines()
            .skip(2)
            .take_while(|l| l.ends_with(" n "))
            .enumerate()
        {
            let off: usize = entry.split(' ').next().unwrap().parse().unwrap();
            assert!(
                text[off..].starts_with(&format!("{} 0 obj", i + 1)),
                "object {} is not at its xref offset {off}",
                i + 1
            );
        }
    }

    #[test]
    fn long_content_paginates() {
        let mut pdf = Pdf::new();
        for i in 0..200 {
            pdf.kv(&format!("row {i}"), "value");
        }
        let bytes = pdf.finish("test");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let count: usize = text
            .split("/Count ")
            .nth(1)
            .and_then(|t| t.split(' ').next())
            .unwrap()
            .parse()
            .unwrap();
        assert!(count > 1, "200 rows should not fit on one page");
        assert_eq!(text.matches("/Type /Page ").count(), count);
    }
}
