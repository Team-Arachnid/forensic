# Arachnid Forensic — Landing Site Design

Working notes and the final token system for the marketing site. This is the
record of the brainstorm → critique → build process, kept in the repo so the
next person changing a colour knows why it was that colour.

## 1. The one idea

**One thread. Every phase of the case.**

Arachnid is three tools — Core (acquire), Recover (extract), Sanitize (destroy)
— stitched into one suite by a single signed chain-of-custody log. The whole
site is built around that single fact, and so is the one signature element: a
**thread/node network**. It is literally a spider's web, and it is literally
what the product does — weaving one connected evidence trail across three
otherwise-separate tools. That double meaning is the justification for the web
being the signature, not decoration.

The web is a persistent WebGL layer behind the entire page, not a hero toy. Its
state is driven by scroll:

| Scroll phase | Section | Web behaviour |
|---|---|---|
| 0.00–0.14 | Hero | three nodes breathing, threads faint but present |
| 0.14–0.30 | The Fracture | nodes drift apart, threads decay — fragmentation |
| 0.30–0.44 | The Thread | threads redraw between the nodes, node-by-node |
| 0.44–0.74 | Core / Recover / Sanitize | camera settles on each node in turn; the active module's node ignites |
| 0.74–0.88 | The Ledger | web holds steady; signed pulses travel the threads |
| 0.88–1.00 | Footer | the web contracts and resolves toward the Arachnid mark |

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
| `--ink-faint` | `#5A5A61` | tertiary — timestamps, disabled, hairline labels |
| `--thread` | `#C81E3A` | the accent — a deep arterial / sealing-wax crimson. Reads as "sealed evidence thread", not "warning light". Used only for the signature, key CTAs, and small structural marks — never a large fill. |
| `--thread-bright` | `#E23150` | hover / focus lift on `--thread`, and the ignited node in 3D |
| `--thread-dim` | `#4A0B18` | low-opacity borders, glow falloff, hover wells |
| `--line` | `#26262B` | hairline dividers, panel borders |

### Contrast (measured, sRGB, WCAG 2.1 — computed, not eyeballed)

- `--ink` `#F3F2EE` on `--void` `#08080A` → **17.9 : 1** (AAA — body + headings)
- `--ink` on `--surface` `#131316` → **16.6 : 1** (AAA)
- `--ink-muted` `#8D8C92` on `--void` → **6.00 : 1** (AA normal text); on `--surface` **5.56 : 1** (AA)
- `--ink-faint` `#5A5A61` on `--void` → **2.93 : 1** — used **only** for large/≥18.66px or non-essential decoration, never for essential body text.
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
- **Glitch text / scanlines / matrix rain** → rejected. The single motion device
  is the thread web; nothing competes with it.
- **Bright acid alert-red** → rejected in favour of a deep sealing-wax crimson,
  used sparingly and never as a large field.
- **Numbered 01/02/03 with no ordering logic** → the chapters follow the real
  acquire → extract → destroy pipeline; the numbering means something.
- **Stock Heroicons + gradient-blob hero** → the hero centrepiece is the web
  itself; icons are custom line marks echoing the web, no emoji anywhere.
- **Generic FAQ/doc landing pattern** (what the design tool suggested) → rejected;
  this is a single scroll-narrative, not a search-bar-and-accordion template.

## 6. Motion & fallbacks

- One orchestrated device (the web). Micro-interactions (button hover, link
  underline) are quiet and quick (120–180ms), never set-pieces.
- `prefers-reduced-motion`: scroll-scrub and continuous 3D motion are disabled;
  the web is replaced by a static SVG rendering of the same node/thread motif.
- No-WebGL / low-power / touch: the WebGL scene is dynamically imported
  (`ssr: false`), never blocks LCP, and degrades to the same SVG fallback. The
  pinned module chapters degrade to a normal stacked layout below `md`.

## 7. Signature rationale (the justification test)

The brief's bar: the signature must be justified by the subject, not chosen for
its own sake. The web passes because it is doing double duty — a spider's web
(the brand mark is a spider) *and* a faithful diagram of the product (three tool
nodes joined by one thread). Remove the web and you lose the one-sentence pitch;
that is the test for a real signature versus decoration.
