"use client";

import { useState } from "react";

type CopyCommandProps = {
  /** raw text copied to the clipboard */
  command: string;
  /** optional lines to display (defaults to the command split on newlines) */
  display?: string[];
  label?: string;
};

export function CopyCommand({ command, display, label }: CopyCommandProps) {
  const [copied, setCopied] = useState(false);
  const lines = display ?? command.split("\n");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard blocked (e.g. insecure context) — select-to-copy still works.
      setCopied(false);
    }
  };

  return (
    <div className="panel group relative w-full overflow-hidden">
      {label ? (
        <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <span className="flex gap-1.5" aria-hidden="true">
            <span className="h-2.5 w-2.5 rounded-full bg-thread-dim" />
            <span className="h-2.5 w-2.5 rounded-full bg-line" />
            <span className="h-2.5 w-2.5 rounded-full bg-line" />
          </span>
          <span className="data ml-1 text-xs text-ink-faint">{label}</span>
        </div>
      ) : null}

      <div className="flex items-start justify-between gap-4 px-4 py-4 sm:px-5">
        <pre className="data overflow-x-auto text-[0.82rem] leading-relaxed text-ink sm:text-sm">
          {lines.map((line, i) => (
            <div key={i} className="whitespace-pre">
              <span className="mr-3 select-none text-thread" aria-hidden="true">
                $
              </span>
              {line}
            </div>
          ))}
        </pre>

        <button
          type="button"
          onClick={copy}
          aria-label={copied ? "Command copied to clipboard" : "Copy command to clipboard"}
          className="shrink-0 border border-line bg-surface-2/70 px-2.5 py-2 text-ink-muted transition-colors duration-150 hover:border-thread hover:text-ink"
        >
          <span aria-hidden="true">
            {copied ? <CheckGlyph /> : <CopyGlyph />}
          </span>
        </button>
      </div>

      <span aria-live="polite" className="sr-only">
        {copied ? "Copied" : ""}
      </span>
    </div>
  );
}

function CopyGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
      <path
        d="M10.5 5.5V3.7c0-.66-.54-1.2-1.2-1.2H3.7c-.66 0-1.2.54-1.2 1.2v5.6c0 .66.54 1.2 1.2 1.2h1.8"
        stroke="currentColor"
        strokeWidth="1.3"
      />
    </svg>
  );
}

function CheckGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M3 8.5l3.2 3.2L13 5"
        stroke="var(--thread-bright)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
