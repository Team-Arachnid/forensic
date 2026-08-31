"use client";

import { useEffect, useState } from "react";
import { CopyCommand } from "@/components/copy-command";
import { Reveal } from "@/components/reveal";
import { modules, type ModuleId } from "@/lib/site";

function useActiveModule(ids: ModuleId[]): ModuleId {
  const [active, setActive] = useState<ModuleId>(ids[0]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) setActive(visible.target.id as ModuleId);
      },
      { rootMargin: "-45% 0px -45% 0px", threshold: [0, 0.25, 0.5, 1] },
    );
    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [ids]);

  return active;
}

export function Modules() {
  const ids = modules.map((m) => m.id);
  const active = useActiveModule(ids);

  return (
    <section
      id="modules"
      aria-labelledby="modules-heading"
      className="relative py-24 md:py-32"
    >
      <div className="shell">
        <div className="grid gap-12 lg:grid-cols-[280px_1fr] lg:gap-16">
          {/* Sticky index rail — the "pinned" focal navigation on desktop. */}
          <div className="lg:sticky lg:top-24 lg:h-fit lg:self-start">
            <p className="chapter-mark">CH.03&ndash;05 &mdash; The Suite</p>
            <h2
              id="modules-heading"
              className="mt-5 font-display text-3xl font-semibold sm:text-4xl"
            >
              Three modules, one workflow.
            </h2>
            <p className="data mt-4 text-sm text-ink-muted">
              acquire <span className="text-thread">&rarr;</span> extract{" "}
              <span className="text-thread">&rarr;</span> destroy
            </p>

            <ol className="mt-8 hidden border-l border-line lg:block">
              {modules.map((m) => {
                const isActive = m.id === active;
                return (
                  <li key={m.id}>
                    <a
                      href={`#${m.id}`}
                      aria-current={isActive ? "true" : undefined}
                      className={`-ml-px flex items-baseline gap-3 border-l-2 py-2.5 pl-5 transition-colors duration-200 ${
                        isActive
                          ? "border-thread text-ink"
                          : "border-transparent text-ink-faint hover:text-ink-muted"
                      }`}
                    >
                      <span className="data text-xs">{m.index}</span>
                      <span className="font-display text-lg">{m.name}</span>
                      <span className="data ml-auto text-[0.65rem] uppercase tracking-[0.14em]">
                        {m.verb}
                      </span>
                    </a>
                  </li>
                );
              })}
            </ol>
          </div>

          {/* Module panels */}
          <div className="space-y-20 lg:space-y-28">
            {modules.map((m) => (
              <Reveal
                as="section"
                key={m.id}
                className="scroll-mt-24"
              >
                <article id={m.id} className="scroll-mt-24">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <p className="chapter-mark">
                        {m.index} &mdash; {m.name}
                      </p>
                      <h3 className="mt-4 max-w-[22ch] font-display text-[1.9rem] font-semibold leading-tight sm:text-4xl">
                        {m.verb}.{" "}
                        <span className="text-ink-muted">{m.tagline}</span>
                      </h3>
                    </div>
                    <StanceBadge stance={m.stance} />
                  </div>

                  <p className="mt-6 max-w-2xl text-balance text-lg leading-relaxed text-ink-muted">
                    {m.body}
                  </p>

                  <ul className="mt-9 space-y-5">
                    {m.capabilities.map((c, i) => (
                      <li key={c.label} className="border-t border-line pt-5">
                        <div className="flex gap-4">
                          <span className="data mt-1 shrink-0 text-xs text-thread">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <div>
                            <p className="font-medium text-ink">{c.label}</p>
                            <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-ink-muted">
                              {c.detail}
                            </p>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>

                  <div className="mt-8 max-w-xl">
                    <CopyCommand command={m.command} label={m.binary} />
                  </div>
                </article>
              </Reveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function StanceBadge({ stance }: { stance: "read-only" | "destructive" }) {
  const destructive = stance === "destructive";
  return (
    <span
      className={`data inline-flex items-center gap-2 border px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] ${
        destructive
          ? "border-thread text-thread-bright"
          : "border-line text-ink-muted"
      }`}
    >
      <span
        aria-hidden="true"
        className={`h-1.5 w-1.5 rounded-full ${
          destructive ? "bg-thread" : "bg-ink-faint"
        }`}
      />
      {destructive ? "Destroys data" : "Read-only"}
    </span>
  );
}
