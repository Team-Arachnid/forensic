import type { Metadata, Viewport } from "next";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { SmoothScroll } from "@/components/smooth-scroll";
import { SiteNav } from "@/components/site-nav";
import { SiteFooter } from "@/components/site-footer";
import { BackgroundField } from "@/components/background-field";

const mono = JetBrains_Mono({
  subsets: ["latin"],
  display: "swap",
  weight: ["400", "500", "600", "700"],
  variable: "--font-mono-jb",
});

const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL ?? "https://arachnid-forensic.vercel.app";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "Arachnid Forensic — one thread, every phase of the case",
    template: "%s — Arachnid Forensic",
  },
  description:
    "An open-source, unified digital forensics suite: live triage, file recovery, and certified secure erasure, joined by one signed chain-of-custody log. Built in Rust with a terminal UI.",
  keywords: [
    "digital forensics",
    "DFIR",
    "live triage",
    "file recovery",
    "secure erasure",
    "chain of custody",
    "Rust",
    "open source",
    "Arachnid",
  ],
  authors: [{ name: "Arachnid Forensic" }],
  creator: "Arachnid Forensic",
  openGraph: {
    type: "website",
    url: siteUrl,
    title: "Arachnid Forensic — one thread, every phase of the case",
    description:
      "One suite, one signed evidence trail, three modules — acquire, recover, sanitize. Open-source digital forensics built in Rust.",
    siteName: "Arachnid Forensic",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "Arachnid Forensic — one thread, every phase of the case",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Arachnid Forensic — one thread, every phase of the case",
    description:
      "Open-source digital forensics: live triage, file recovery, certified erasure — one signed chain of custody across all three.",
    images: ["/og.png"],
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32.png", type: "image/png", sizes: "32x32" },
      { url: "/favicon-16.png", type: "image/png", sizes: "16x16" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180" }],
  },
  manifest: "/site.webmanifest",
  alternates: { canonical: siteUrl },
};

export const viewport: Viewport = {
  themeColor: "#08080a",
  colorScheme: "dark",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={mono.variable} suppressHydrationWarning>
      <head>
        {/* Display + body faces from Fontshare. Preconnect keeps the fetch
            off the critical path; the fallback stacks render immediately. */}
        <link rel="preconnect" href="https://api.fontshare.com" />
        <link
          rel="preconnect"
          href="https://cdn.fontshare.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://api.fontshare.com/v2/css?f[]=clash-display@500,600,700&f[]=general-sans@400,500,600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        <SmoothScroll>
          <BackgroundField />
          <SiteNav />
          <main id="main">{children}</main>
          <SiteFooter />
        </SmoothScroll>
      </body>
    </html>
  );
}
