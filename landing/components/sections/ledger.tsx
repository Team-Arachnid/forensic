"use client";

import { useEffect, useRef, useState } from "react";
import { Reveal } from "@/components/reveal";
import { useReducedMotion } from "@/lib/use-reduced-motion";

type Record = {
  seq: string;
  phase: string;
  subject: string;
  sha: string;
  prev: string;
  utc: string;
};

const records: Record[] = [
  { seq: "01", phase: "core.collect", subject: "artifacts/processes.json", sha: "a41b…d0", prev: "0000…00", utc: "09:12:33Z" },
  { seq: "02", phase: "core.collect", subject: "artifacts/connections.json", sha: "5e7c…19", prev: "a41b…d0", utc: "09:12:34Z" },
  { seq: "03", phase: "core.capture", subject: "artifacts/capture.pcap", sha: "b8f0…7a", prev: "5e7c…19", utc: "09:18:02Z" },
  { seq: "04", phase: "core.parse", subject: "artifacts/pcap_analysis.json", sha: "1c93…e4", prev: "b8f0…7a", utc: "09:24:51Z" },
  { seq: "05", phase: "recover.scan", subject: "artifacts/results.json", sha: "7c1e…9b", prev: "1c93…e4", utc: "10:03:20Z" },
  { seq: "06", phase: "recover.export", subject: "recovered/Cases/evidence-photo.jpg", sha: "d20a…33", prev: "7c1e…9b", utc: "10:07:44Z" },
  { seq: "07", phase: "sanitize.wipe", subject: "sdb · nist-clear · verified read-back", sha: "44fe…c1", prev: "d20a…33", utc: "14:20:06Z" },
  { seq: "08", phase: "sanitize.cert", subject: "certificates/cert-0007.json", sha: "9af2…08", prev: "44fe…c1", utc: "14:59:11Z" },
];

export function Ledger() {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(reduced ? records.length : 0);
  const started = useRef(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (reduced) {
      setShown(records.length);
      return;
    }
    // Begin streaming only once the panel scrolls into view.
    const el = containerRef.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !started.current) {
          started.current = true;
          let i = 0;
          const tick = () => {
            i += 1;
            setShown(i);
            if (i < records.length) {
              timer = window.setTimeout(tick, 420);
            }
          };
          let timer = window.setTimeout(tick, 300);
        }
      },
      { threshold: 0.35 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [reduced]);

  const complete = shown >= records.length;

  return (
    <section
      id="ledger"
      aria-labelledby="ledger-heading"
      className="relative py-28 md:py-40"
    >
      <div className="shell">
        <div className="grid gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)] lg:items-center lg:gap-16">
          <Reveal>
            <p className="chapter-mark">The Ledger</p>
            <h2
              id="ledger-heading"
              className="mt-6 max-w-[16ch] font-display text-[2rem] font-semibold sm:text-5xl"
            >
              Auditable, not a black box.
            </h2>
            <p className="mt-6 max-w-xl text-balance text-lg leading-relaxed text-ink-muted">
              Every phase writes to one append-only <span className="data text-ink">custody.log</span>.
              Each line signs the exact bytes of a record and chains to the hash
              of the last, so the whole case is one verifiable object.
            </p>
            <ul className="mt-8 space-y-3 text-sm text-ink-muted">
              <li className="flex gap-3">
                <span className="data text-thread-bright">verify</span>
                <span>re-hashes every artifact and re-checks every signature — implemented independently of collection.</span>
              </li>
              <li className="flex gap-3">
                <span className="data text-thread-bright">exit 0</span>
                <span>intact. <span className="data text-ink">exit 3</span> tampered — stable across releases, for IR scripts.</span>
              </li>
              <li className="flex gap-3">
                <span className="data text-thread-bright">chain</span>
                <span>delete or reorder a record and the prev-hash link breaks visibly.</span>
              </li>
            </ul>
          </Reveal>

          <Reveal delay={0.1}>
            <div ref={containerRef} className="panel overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                <div className="flex items-center gap-2.5">
                  <span className="flex gap-1.5" aria-hidden="true">
                    <span className="h-2.5 w-2.5 rounded-full bg-thread-dim" />
                    <span className="h-2.5 w-2.5 rounded-full bg-line" />
                    <span className="h-2.5 w-2.5 rounded-full bg-line" />
                  </span>
                  <span className="data text-xs text-ink-faint">
                    custody.log &mdash; case-4471
                  </span>
                </div>
                <span
                  className={`data flex items-center gap-1.5 text-[0.65rem] uppercase tracking-[0.14em] ${
                    complete ? "text-thread-bright" : "text-ink-faint"
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`h-1.5 w-1.5 rounded-full ${
                      complete ? "bg-thread" : "bg-ink-faint"
                    }`}
                  />
                  chain intact
                </span>
              </div>

              <div className="min-h-[19rem] px-4 py-4 sm:min-h-[21rem]">
                <ol className="space-y-1.5" aria-label="Signed chain-of-custody records">
                  {records.slice(0, shown).map((r) => (
                    <li key={r.seq} className="data text-[0.72rem] leading-relaxed sm:text-xs">
                      <span className="text-thread-bright">sig</span>{" "}
                      <span className="text-ink-faint">{r.sha}</span>{" "}
                      <span className="text-ink-muted">seq={r.seq}</span>{" "}
                      <span className="text-ink">{r.phase}</span>{" "}
                      <span className="text-ink-muted">{r.subject}</span>{" "}
                      <span className="text-ink-faint">prev={r.prev}</span>
                    </li>
                  ))}
                </ol>

                {complete ? (
                  <p className="data mt-4 border-t border-line pt-3 text-[0.72rem] sm:text-xs">
                    <span className="text-ink-muted">
                      $ arachnid-core verify ./ev-host01
                    </span>{" "}
                    <span className="text-thread-bright">→ OK</span>{" "}
                    <span className="text-ink-faint">
                      exit 0 · 8 artifacts · chain intact
                    </span>
                  </p>
                ) : (
                  <p
                    className="data mt-4 text-xs text-thread-bright"
                    aria-hidden="true"
                  >
                    <span className="inline-block h-3.5 w-2 animate-caret bg-thread align-middle" />
                  </p>
                )}
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
