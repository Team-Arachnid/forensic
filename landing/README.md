# Arachnid Forensic — landing site

The marketing site for the Arachnid Forensic suite. A static Next.js (App
Router, TypeScript) app: one scroll-driven narrative, no backend, no CMS, no API
routes.

## Stack

- **Next.js** (App Router) + **TypeScript**, statically generated.
- **Tailwind CSS** layered on a custom CSS-variable token theme — the default
  Tailwind palette is replaced, not extended. See `app/globals.css` and
  [`DESIGN.md`](./DESIGN.md).
- **React Three Fiber + three** for the signature thread/node web, dynamically
  imported (no SSR) with an SVG fallback for reduced-motion and no-WebGL.
- **GSAP + ScrollTrigger** for scroll reveals, **Lenis** for smooth scroll —
  both disabled under `prefers-reduced-motion`.
- Fonts: Clash Display + General Sans (Fontshare) for display/body, JetBrains
  Mono (`next/font`) for data.

## Develop

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # production build (static)
npm start          # serve the production build
```

## Brand assets

Favicons, the web manifest, the OG image and the brand marks are generated from
the source logos in `../media` and committed as static files:

```bash
npm run assets
```

The Vercel build never runs this script or depends on any font/text backend at
deploy time — it only serves the committed output in `public/`.

## Deploy (Vercel)

This app lives in the `landing/` subdirectory of the repository. When importing
the project into Vercel, set **Root Directory = `landing`**. No other
configuration is required; the framework preset (Next.js), build command and
output are detected automatically.

Set `NEXT_PUBLIC_SITE_URL` to the canonical production URL so Open Graph and
canonical tags resolve to absolute URLs.

## Accessibility & motion

- WCAG AA contrast verified on the dark palette (see `DESIGN.md §2`).
- Visible keyboard focus on every interactive element.
- `prefers-reduced-motion` disables scroll-scrub and continuous 3D; the SVG web
  fallback replaces the WebGL scene.
- Responsive to 375px; the module chapters degrade from the sticky index layout
  to a stacked layout below `lg`.
