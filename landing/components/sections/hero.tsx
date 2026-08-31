import { CopyCommand } from "@/components/copy-command";
import { links, install } from "@/lib/site";

export function Hero() {
  return (
    <section
      id="hero"
      aria-labelledby="hero-heading"
      className="relative flex min-h-[100svh] flex-col justify-center pb-20 pt-28"
    >
      <div className="shell">
        <p className="eyebrow">
          Unified digital forensics
          <span className="mx-2 text-thread-bright">/</span>
          built in Rust
        </p>

        <h1
          id="hero-heading"
          className="mt-7 max-w-[16ch] font-display text-[2.7rem] font-semibold leading-[1.02] tracking-display text-ink sm:text-6xl lg:text-[5.2rem]"
        >
          One thread.
          <br />
          <span className="text-ink">Every phase of the case.</span>
        </h1>

        <p className="mt-7 max-w-2xl text-balance text-lg leading-relaxed text-ink-muted sm:text-xl">
          Core acquires, Recover extracts, Sanitize destroys — three modules
          stitched into one suite by a single signed chain-of-custody log that
          survives every handoff.
        </p>

        <div className="mt-10 flex flex-col gap-5 lg:flex-row lg:items-stretch">
          <div className="w-full max-w-xl">
            <CopyCommand command={install.unix} label="install.sh — macOS · Linux" />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <a
              href={links.repo}
              className="inline-flex h-11 items-center gap-2 bg-thread px-5 text-sm font-semibold text-ink transition-colors duration-150 hover:bg-thread-bright focus-visible:outline-offset-4"
            >
              Star on GitHub
            </a>
            <a
              href={links.docs}
              className="inline-flex h-11 items-center gap-2 border border-line bg-surface/50 px-5 text-sm font-medium text-ink transition-colors duration-150 hover:border-thread"
            >
              Read the docs
            </a>
          </div>
        </div>

        <dl className="mt-14 grid max-w-3xl grid-cols-1 gap-x-8 gap-y-4 border-t border-line pt-8 data text-xs text-ink-faint sm:grid-cols-3">
          <div>
            <dt className="text-thread-bright">Read-only by design</dt>
            <dd className="mt-1 text-ink-muted">Collectors never write to the target host.</dd>
          </div>
          <div>
            <dt className="text-thread-bright">Tamper-evident</dt>
            <dd className="mt-1 text-ink-muted">Ed25519-signed, hash-chained custody log.</dd>
          </div>
          <div>
            <dt className="text-thread-bright">Standards-mapped</dt>
            <dd className="mt-1 text-ink-muted">NIST 800-88 / DoD 5220.22-M erasure.</dd>
          </div>
        </dl>
      </div>

      <div
        aria-hidden="true"
        className="pointer-events-none absolute bottom-7 left-1/2 hidden -translate-x-1/2 flex-col items-center gap-2 md:flex"
      >
        <span className="data text-[0.65rem] uppercase tracking-[0.3em] text-ink-faint">
          Scroll
        </span>
        <span className="h-10 w-px bg-gradient-to-b from-thread to-transparent" />
      </div>
    </section>
  );
}
