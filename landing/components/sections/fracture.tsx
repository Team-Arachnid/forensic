import { Reveal } from "@/components/reveal";

const fragments = [
  {
    tool: "triage tool",
    stamp: "2024-11-04 09:12:33Z",
    line: "collected procs=182 net=44 · sha256 per-file",
    custody: "log → triage_run.txt (local)",
  },
  {
    tool: "recovery tool",
    stamp: "11/04/24 9:47 AM",
    line: "recovered 128 files → E:\\out",
    custody: "log → none",
  },
  {
    tool: "erasure tool",
    stamp: "Mon Nov  4 14:20:06",
    line: "wipe sdb PASS 3/3 OK",
    custody: "certificate → none",
  },
];

export function Fracture() {
  return (
    <section
      id="fracture"
      aria-labelledby="fracture-heading"
      className="relative py-28 md:py-40"
    >
      <div className="shell">
        <Reveal>
          <p className="chapter-mark">CH.01 — The Fracture</p>
          <h2
            id="fracture-heading"
            className="mt-6 max-w-[18ch] font-display text-[2.1rem] font-semibold sm:text-5xl"
          >
            Three tools. Three logs. No shared thread.
          </h2>
          <p className="mt-6 max-w-2xl text-balance text-lg leading-relaxed text-ink-muted">
            A single case runs through at least three tools: one to triage the
            live host, one to pull deleted files back, one to certify the media
            was destroyed once it&rsquo;s closed. Each writes its own log, in its
            own format, with its own clock. Stitching them into one defensible
            timeline is manual, lossy, and exactly the seam a challenge is built
            to pry open.
          </p>
        </Reveal>

        <Reveal className="mt-14 grid gap-5 md:grid-cols-3" stagger={0.12}>
          {fragments.map((f) => (
            <div
              key={f.tool}
              className="panel flex flex-col gap-4 p-5"
            >
              <div className="flex items-center justify-between">
                <span className="eyebrow text-ink-muted">{f.tool}</span>
                <span
                  aria-hidden="true"
                  className="h-2 w-2 rounded-full border border-ink-faint"
                />
              </div>
              <p className="data text-xs text-ink-faint">{f.stamp}</p>
              <p className="data text-sm leading-relaxed text-ink">{f.line}</p>
              <p className="data mt-auto border-t border-line pt-3 text-xs text-thread-bright">
                {f.custody}
              </p>
            </div>
          ))}
        </Reveal>

        <Reveal className="mt-10">
          <p className="max-w-2xl text-base leading-relaxed text-ink-muted">
            Nothing binds the second record to the first. Different timestamps,
            no shared hashes, no chain that a third party can re-verify from end
            to end.{" "}
            <span className="text-ink">
              The evidence is real; the trail connecting it is improvised.
            </span>
          </p>
        </Reveal>
      </div>
    </section>
  );
}
