"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { links } from "@/lib/site";

const sections = [
  { id: "fracture", label: "Problem" },
  { id: "modules", label: "Modules" },
  { id: "ledger", label: "Ledger" },
  { id: "install", label: "Install" },
];

export function SiteNav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-colors duration-300 ${
        scrolled
          ? "border-b border-line bg-void/80 backdrop-blur-md"
          : "border-b border-transparent"
      }`}
    >
      <nav
        aria-label="Primary"
        className="shell flex h-16 items-center justify-between gap-6"
      >
        <a
          href="#top"
          className="group flex items-center gap-2.5"
          aria-label="Arachnid Forensic — home"
        >
          <Image
            src="/brand/mark.png"
            alt=""
            width={28}
            height={28}
            priority
            className="h-7 w-7"
          />
          <span className="font-display text-[0.95rem] font-semibold tracking-display text-ink">
            Arachnid
            <span className="text-ink-muted"> Forensic</span>
          </span>
        </a>

        <ul className="hidden items-center gap-7 md:flex">
          {sections.map((s) => (
            <li key={s.id}>
              <a
                href={`#${s.id}`}
                className="link-quiet data text-[0.8rem] uppercase tracking-[0.14em] text-ink-muted"
              >
                {s.label}
              </a>
            </li>
          ))}
        </ul>

        <div className="flex items-center gap-3">
          <a
            href={links.docs}
            className="link-quiet data hidden text-[0.8rem] uppercase tracking-[0.14em] text-ink-muted sm:inline"
          >
            Docs
          </a>
          <a
            href={links.repo}
            className="inline-flex items-center gap-2 border border-line bg-surface/60 px-3.5 py-2 text-[0.8rem] font-medium text-ink transition-colors duration-150 hover:border-thread hover:text-ink"
          >
            <GitHubGlyph />
            <span className="data tracking-[0.06em]">GitHub</span>
          </a>
        </div>
      </nav>
    </header>
  );
}

function GitHubGlyph() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}
