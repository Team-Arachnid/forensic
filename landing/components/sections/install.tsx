import { Reveal } from "@/components/reveal";
import { CopyCommand } from "@/components/copy-command";
import { install, links } from "@/lib/site";

export function Install() {
  return (
    <section
      id="install"
      aria-labelledby="install-heading"
      className="relative py-28 md:py-40"
    >
      <div className="shell">
        <Reveal className="max-w-2xl">
          <p className="chapter-mark">Install</p>
          <h2
            id="install-heading"
            className="mt-6 font-display text-[2rem] font-semibold sm:text-5xl"
          >
            One line. Read it before you run it.
          </h2>
          <p className="mt-6 text-balance text-lg leading-relaxed text-ink-muted">
            The installer downloads to a file rather than piping into a shell, so
            you can read it first. It verifies a signature over the digest file,
            then the digest of the binary, and aborts on either failure having
            installed nothing &mdash; no telemetry, no privilege escalation of
            its own.
          </p>
        </Reveal>

        <Reveal className="mt-12 grid gap-5 md:grid-cols-2" stagger={0.1}>
          <div>
            <p className="eyebrow mb-3">macOS · Linux</p>
            <CopyCommand command={install.unix} label="install.sh" />
          </div>
          <div>
            <p className="eyebrow mb-3">Windows (PowerShell)</p>
            <CopyCommand command={install.windows} label="install.ps1" />
          </div>
        </Reveal>

        <Reveal className="mt-8 flex flex-col gap-4 border-t border-line pt-8 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-xl text-sm leading-relaxed text-ink-muted">
            Prefer a package manager, an air-gapped install, or building from
            source? Those paths &mdash; and exactly what the installer touches on
            disk and on the network &mdash; are documented in full.
          </p>
          <div className="flex shrink-0 flex-wrap gap-3">
            <a
              href={links.docs}
              className="inline-flex h-10 items-center gap-2 border border-line bg-surface/50 px-4 text-sm font-medium text-ink transition-colors duration-150 hover:border-thread"
            >
              Install guide
            </a>
            <a
              href={links.threatModel}
              className="link-quiet inline-flex h-10 items-center text-sm text-ink-muted"
            >
              Installer threat model
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
