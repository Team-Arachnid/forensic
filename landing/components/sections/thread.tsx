import { Reveal } from "@/components/reveal";

export function Thread() {
  return (
    <section
      id="thread"
      aria-labelledby="thread-heading"
      className="relative py-28 md:py-44"
    >
      <div className="shell">
        <Reveal className="mx-auto max-w-3xl text-center">
          <div className="flex justify-center">
            <p className="chapter-mark">CH.02 — The Thread</p>
          </div>

          <h2
            id="thread-heading"
            className="mt-8 font-display text-[2rem] font-semibold leading-tight sm:text-5xl"
          >
            One signed log, carried across every phase of the case.
          </h2>

          <p className="mx-auto mt-8 max-w-2xl text-balance text-lg leading-relaxed text-ink-muted">
            Every action &mdash; acquire, recover, sanitize &mdash; appends one
            record to a single append-only custody log. Each line is
            Ed25519-signed over its exact bytes and chained to the hash of the
            record before it. Edit an artifact and its digest stops matching;
            reorder a line and the chain breaks. The trail is no longer
            improvised &mdash; it is one object a third party can re-verify from
            end to end.
          </p>
        </Reveal>

        <Reveal className="mx-auto mt-12 max-w-2xl" delay={0.1}>
          <div className="panel p-4 sm:p-5">
            <p className="data text-xs leading-relaxed text-ink-muted">
              <span className="text-thread-bright">sig</span> 3f9a2c…e1c
              <span className="mx-2 text-ink-faint">·</span>
              <span className="text-ink">
                {'{'}&quot;seq&quot;:7,&quot;phase&quot;:&quot;recover&quot;,&quot;prev&quot;:&quot;a17e…&quot;,
              </span>
            </p>
            <p className="data mt-1 pl-[2.4rem] text-xs leading-relaxed text-ink">
              &quot;utc&quot;:&quot;2024-11-04T14:22:06Z&quot;,&quot;mono_ms&quot;:18734{'}'}
            </p>
            <p className="data mt-3 border-t border-line pt-3 text-[0.7rem] uppercase tracking-[0.16em] text-ink-faint">
              one record · signed · chained to the last
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
