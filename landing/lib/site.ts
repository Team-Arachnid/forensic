/** Canonical external links and product data — single source for the whole site. */

export const links = {
  repo: "https://github.com/Team-Arachnid/forensic",
  wiki: "https://github.com/Team-Arachnid/forensic/wiki",
  docs: "https://team-arachnid.github.io/forensic/",
  license: "https://github.com/Team-Arachnid/forensic/blob/main/LICENSE",
  threatModel:
    "https://github.com/Team-Arachnid/forensic/blob/main/THREAT_MODEL.md",
} as const;

export const install = {
  unix: `curl -fsSL https://raw.githubusercontent.com/Team-Arachnid/forensic/main/install.sh -o install.sh
sh install.sh`,
  windows: `irm https://raw.githubusercontent.com/Team-Arachnid/forensic/main/install.ps1 -OutFile install.ps1
.\\install.ps1`,
} as const;

export type ModuleId = "core" | "recover" | "sanitize";

export type ModuleSpec = {
  id: ModuleId;
  index: string;
  name: string;
  verb: string;
  binary: string;
  stance: "read-only" | "destructive";
  tagline: string;
  body: string;
  capabilities: { label: string; detail: string }[];
  command: string;
};

export const modules: ModuleSpec[] = [
  {
    id: "core",
    index: "CH.03",
    name: "Core",
    verb: "Acquire",
    binary: "arachnid-core",
    stance: "read-only",
    tagline: "Live triage and network forensics, read-only against the target.",
    body: "Core collects volatile system state and network evidence from a running host into a tamper-evident, signed container. The only writes go to the container directory you name — collectors read /proc, /sys and the registry (KEY_READ only), and enumerate persistence rather than touching it.",
    capabilities: [
      {
        label: "Volatile state",
        detail:
          "Processes with argv, parent PID, loaded modules and the SHA-256 of each on-disk image; connections mapped to owning processes; sessions, kernel modules and persistence locations.",
      },
      {
        label: "Network capture",
        detail:
          "Kernel-applied BPF filters so unmatched traffic is never copied to userspace; promiscuous mode off by default; drops recorded and surfaced, because gaps in evidence must be visible.",
      },
      {
        label: "Independent verify",
        detail:
          "verify re-hashes every artifact, re-checks every signature and walks the custody chain — implemented separately from collection, so a collection bug can't make a broken container read clean.",
      },
    ],
    command: "arachnid-core collect -o ./ev-host01 --operator analyst-7",
  },
  {
    id: "recover",
    index: "CH.04",
    name: "Recover",
    verb: "Extract",
    binary: "arachnid-recover",
    stance: "read-only",
    tagline: "Pull deleted files back — filesystem-aware, then carved.",
    body: "Recover reconstructs files from an image or an attached device by parsing filesystem metadata and by carving raw sectors. It is structurally read-only: the Source trait every parser reads through has no write method, and handles are opened read-only so the OS refuses a write even if one were issued.",
    capabilities: [
      {
        label: "Two passes, two claims",
        detail:
          "The filesystem pass (NTFS MFT, ext4 inodes and jbd2 journal) recovers contents plus original name, path and timestamps. Carving recovers content only — and is never presented as though it recovered more.",
      },
      {
        label: "Confidence scoring",
        detail:
          "Every result carries a label and the checks behind it. The rule that does the most work: a deleted file never scores High, because its clusters are free and a clean read proves the bytes are readable, not that they're still that file's bytes.",
      },
      {
        label: "Export is evidence",
        detail:
          "Every exported file is hashed as it's written into the same signed custody log a triage collection uses — a recovery export verifies with arachnid-core verify, unchanged.",
      },
    ],
    command: "arachnid-recover scan -i disk.img --carve-pass -o ./rec",
  },
  {
    id: "sanitize",
    index: "CH.05",
    name: "Sanitize",
    verb: "Destroy",
    binary: "arachnid-sanitize",
    stance: "destructive",
    tagline: "Standards-compliant erasure, verified by read-back, certified.",
    body: "Sanitize is the one module that writes to the target. It performs NIST SP 800-88 and DoD 5220.22-M erasure, verifies the result by reading media back byte-for-byte, and issues an Ed25519-signed certificate. A failed verification, a cancelled wipe, or any unwritable region blocks certificate issuance.",
    capabilities: [
      {
        label: "Standards mapping",
        detail:
          "NIST 800-88 Clear (1 pass), DoD 5220.22-M 3- and 7-pass, with byte sequences asserted in tests. Honest about limits: no unverifiable hardware-purge or crypto-erase claim is ever issued.",
      },
      {
        label: "Structural safety rails",
        detail:
          "The write path accepts only a Clearance token, built solely by the authorize check: a typed serial that must match case-sensitively, a system-volume block, device re-enumeration, and a cooldown — no code path reaches a wipe without them.",
      },
      {
        label: "Signed certificates",
        detail:
          "Issued as self-contained JSON, Markdown and HTML, appended to a hash-chained register. Remove an entry and the chain breaks; edit one and its signature fails. Verify with arachnid-sanitize cert --verify.",
      },
    ],
    command: "arachnid-sanitize wipe /dev/sdb --method nist-clear --dry-run",
  },
];
