import Image from "next/image";
import { links } from "@/lib/site";

const columns: { title: string; items: { label: string; href: string }[] }[] = [
  {
    title: "Project",
    items: [
      { label: "GitHub repository", href: links.repo },
      { label: "Wiki", href: links.wiki },
      { label: "Documentation", href: links.docs },
    ],
  },
  {
    title: "Reference",
    items: [
      { label: "Installer threat model", href: links.threatModel },
      { label: "License", href: links.license },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="relative border-t border-line bg-void">
      <div className="shell py-16 md:py-24">
        {/* The mark, resolved. */}
        <div className="mb-14 flex flex-col items-center text-center">
          <div className="relative flex h-40 w-40 items-center justify-center">
            <div
              aria-hidden="true"
              className="absolute inset-0"
              style={{
                background:
                  "radial-gradient(circle at center, rgba(200,30,58,0.18), transparent 66%)",
              }}
            />
            <Image
              src="/brand/mark.png"
              alt="Arachnid Forensic"
              width={128}
              height={128}
              className="relative h-28 w-28 [animation:web-settle_1200ms_cubic-bezier(0.22,1,0.36,1)_both]"
            />
          </div>
          <p className="mt-6 max-w-md text-balance font-display text-lg text-ink">
            One thread. Every phase of the case.
          </p>
          <p className="data mt-3 text-xs uppercase tracking-[0.2em] text-ink-faint">
            Acquire · Extract · Destroy
          </p>
        </div>

        <div className="grid gap-10 border-t border-line pt-12 sm:grid-cols-2 md:grid-cols-[1.4fr_1fr_1fr]">
          <div>
            <p className="font-display text-base font-semibold text-ink">
              Arachnid Forensic
            </p>
            <p className="mt-3 max-w-xs text-sm leading-relaxed text-ink-muted">
              An open-source, unified digital forensics suite built in Rust.
              Live triage, file recovery, and certified secure erasure — one
              signed chain of custody across all three.
            </p>
            <p className="data mt-5 text-xs text-ink-faint">
              For authorized DFIR use only.
            </p>
          </div>

          {columns.map((col) => (
            <nav key={col.title} aria-label={col.title}>
              <p className="eyebrow mb-4">{col.title}</p>
              <ul className="space-y-3">
                {col.items.map((item) => (
                  <li key={item.href}>
                    <a
                      href={item.href}
                      className="link-quiet text-sm text-ink-muted"
                    >
                      {item.label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </div>

        <div className="mt-12 flex flex-col gap-3 border-t border-line pt-8 text-sm text-ink-faint sm:flex-row sm:items-center sm:justify-between">
          <p className="data text-xs">
            Released under the terms in the repository LICENSE.
          </p>
          <p className="data text-xs">
            Be inspectable, not evasive. Never write to the target.
          </p>
        </div>
      </div>
    </footer>
  );
}
