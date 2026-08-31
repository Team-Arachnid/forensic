# Arachnid Forensic — Landing Site Design

Working notes and the final token system for the marketing site. This is the
record of the brainstorm → critique → build process, kept in the repo so the
next person changing a colour knows why it was that colour.

## 1. The one idea

**One thread. Every phase of the case.**

Arachnid is three tools — Core (acquire), Recover (extract), Sanitize (destroy)
— stitched into one suite by a single signed chain-of-custody log. The whole
site is built around that single fact, and so is the one signature element: the
**Arachnid mark itself** — the spider-in-web emblem. It is the brand, and it is
literally what the product is: a web that ties three otherwise-separate tools
into one connected evidence trail. That double meaning is why the mark, not a
decorative device, is the throughline.

The mark recurs, quietly, in two places so the page reads as one object:

- a single large, faint watermark of the mark fixed behind the entire page —
  present but never competing with copy (opacity ≈ 0.055, under a vignette scrim);
- resolved at full strength in the footer, over a soft crimson glow, as the page
  lands on the thesis line.

The narrative itself carries the motion: scroll-reveals, the streaming custody
log, and the crimson `--thread` accent do the work a WebGL scene used to. The
signature is the mark, held consistently, not an effect layered over the page.

## 2. Colour tokens

Named and deliberate. Not generic vermilion/acid-green — a forensic tool that
looked like a generic "hacker" site would undercut its own seriousness.

| Token | Hex | Role |
|---|---|---|
| `--void` | `#08080A` | primary background — near-black, faint cool tint, not pure `#000` |
| `--surface` | `#131316` | raised panels/cards |
| `--surface-2` | `#1B1B1F` | inset wells, code blocks, table rows |
| `--ink` | `#F3F2EE` | primary text — warm off-white, not pure `#FFF` (pure white on near-black vibrates over long reading) |
| `--ink-muted` | `#8D8C92` | secondary text, captions, metadata |
| `--ink-faint` | `#807F86` | tertiary — timestamps, data annotations, hairline labels |
| `--thread` | `#C81E3A` | the accent — a deep arterial / sealing-wax crimson. Reads as "sealed evidence thread", not "warning light". Used only for the signature, key CTAs, and small structural marks — never a large fill. |
| `--thread-bright` | `#E23150` | hover / focus lift on `--thread`, and the ignited node in 3D |
| `--thread-dim` | `#4A0B18` | low-opacity borders, glow falloff, hover wells |
| `--line` | `#26262B` | hairline dividers, panel borders |

### Contrast (measured, sRGB, WCAG 2.1 — computed, not eyeballed)

- `--ink` `#F3F2EE` on `--void` `#08080A` → **17.9 : 1** (AAA — body + headings)
- `--ink` on `--surface` `#131316` → **16.6 : 1** (AAA)
- `--ink-muted` `#8D8C92` on `--void` → **6.00 : 1** (AA normal text); on `--surface` **5.56 : 1** (AA)
- `--ink-faint` `#807F86` on `--void` → **5.05 : 1** (AA); on `--surface` **4.68 : 1** (AA) — the tertiary tier for timestamps, hashes and data annotations. Kept dimmer than `--ink-muted` so the hierarchy reads, but lifted to clear AA rather than sit below it.
- `--thread` `#C81E3A` on `--void` → **3.53 : 1** — passes AA for **large text only** (≥18.66px or ≥14px bold) and for non-text UI marks. Red-on-black is the classic quiet-fail combination, which is exactly why this was measured: crimson is **not** used for small body links.
- `--thread-bright` `#E23150` on `--void` → **4.56 : 1** — the crimson used for **small** text and inline links, because it clears the 4.5:1 AA threshold where `--thread` does not.
- `--ink` on `--thread` fill (off-white label on crimson button) → **5.06 : 1** (AA) — so the primary CTA is a genuine crimson fill with off-white label, verified rather than assumed.

## 3. Type roles

Three roles, none of them a generic default (no Inter/Helvetica headline).

- **Display — Clash Display (Fontshare).** Geometric, industrial, technical. Hero
  headline and chapter titles only, large sizes, tight tracking (`-0.02em`).
- **Body — General Sans (Fontshare).** Humanist sans, legible at small sizes for
  the long-form narrative copy. Never the same family as display.
- **Data / mono — JetBrains Mono (Google Fonts, self-hosted via `next/font`).**
  Hashes, timestamps, exit codes, install commands, the custody-log stream, the
  small "CH.0x" chapter marks. This is not decorative: the product is a CLI/TUI,
  so data-looking text genuinely renders as data.

Fallback stacks are defined so the page is fully legible before or without the
Fontshare fetch. Type scale is fluid (`clamp()`), base body 16px, line-height
1.6 for narrative, 1.3 for display.

## 4. Layout

Scroll-driven narrative, full-bleed sections over the fixed web, content held in
`--surface` panels with `--line` hairlines so it stays readable above the 3D.
Section order carries real logic — it is the actual pipeline, not arbitrary
01/02/03 numbering:

```
HERO         one thread / install / repo + docs
CH.01 Fracture   the problem: three tools, three logs, no shared trail
CH.02 Thread     the turn: one signed custody log across all three phases
CH.03 Core       acquire  — live triage + network capture (read-only)
CH.04 Recover    extract  — filesystem-aware + carving, confidence-scored
CH.05 Sanitize   destroy  — NIST/DoD erasure, signed certificates
Ledger       the signed hash-chained custody log, as a live terminal stream
Install      the real one-line installer + copy button
Footer       threads resolve into the mark; repo / wiki / docs
```

The chapter numbers are `CH.01`–`CH.05` because the page *is* a case file read
top to bottom, not a feature grid.

## 5. Critique against genericism (what was deliberately cut)

The default "dark security site" and the generic design-tool suggestion both
pushed toward the same clichés. Each was rejected on purpose:

- **Terminal-green-on-black** → rejected. Accent is arterial crimson (`--thread`),
  which carries the "sealed evidence" meaning the product is actually about.
- **Glitch text / scanlines / matrix rain** → rejected. Motion is limited to
  quiet scroll-reveals and the streaming custody log; nothing competes for
  attention.
- **Bright acid alert-red** → rejected in favour of a deep sealing-wax crimson,
  used sparingly and never as a large field.
- **Numbered 01/02/03 with no ordering logic** → the chapters follow the real
  acquire → extract → destroy pipeline; the numbering means something.
- **Stock Heroicons + gradient-blob hero** → the hero leads with the thesis
  headline and the real install command; the Arachnid mark recurs as a quiet
  watermark, and no emoji is used anywhere.
- **Generic FAQ/doc landing pattern** (what the design tool suggested) → rejected;
  this is a single scroll-narrative, not a search-bar-and-accordion template.

## 6. Motion & fallbacks

- The background is a **static** logo watermark — no WebGL, no scroll coupling,
  nothing to block LCP. Micro-interactions (button hover, link underline) are
  quiet and quick (120–180ms), never set-pieces.
- `prefers-reduced-motion`: smooth scroll (Lenis), scroll-reveals, the custody-log
  stream and the footer mark settle are all disabled; the page renders fully and
  statically. The watermark is unaffected because it never moved.
- Responsive: the pinned module chapters degrade from the sticky index layout to
  a normal stacked layout below `lg`; verified no horizontal scroll from 375px up.

## 7. Signature rationale (the justification test)

The brief's bar: the signature must be justified by the subject, not chosen for
its own sake. The Arachnid mark passes because it is doing double duty — a
spider's web (the brand is a spider) *and* a picture of the product (a web that
binds three separate tools into one evidence trail). Holding that single mark
consistently — faint behind the page, resolved in the footer — is the throughline;
it is the brand and the pitch in one object, not decoration.
